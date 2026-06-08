package mirror

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xray-distribute/internal/model"
)

// QueueStats 队列统计指标
type QueueStats struct {
	Name         string  `json:"name"`
	Length       int     `json:"length"`        // 当前队列长度
	Capacity     int     `json:"capacity"`      // 队列容量
	UsagePct     float64 `json:"usage_pct"`     // 使用率 0-100
	TotalIn      int64   `json:"total_in"`      // 总入队数
	TotalOut     int64   `json:"total_out"`     // 总出队数
	TotalDropped int64   `json:"total_dropped"` // 总丢弃数
	RateIn       float64 `json:"rate_in"`       // 每秒入队速率
	RateOut      float64 `json:"rate_out"`      // 每秒出队速率
}

// FlowController 流速控制器
type FlowController struct {
	mu           sync.Mutex
	maxQPS       int           // 最大每秒发送到xray的请求数
	currentQPS   int           // 当前QPS限制
	tokenBucket  chan struct{} // 令牌桶
	enabled      bool          // 是否启用限流
	adaptiveMode bool          // 自适应模式：根据队列深度自动调速
}

// NewFlowController 创建流速控制器
func NewFlowController(maxQPS int) *FlowController {
	fc := &FlowController{
		maxQPS:       maxQPS,
		currentQPS:   maxQPS,
		enabled:      maxQPS > 0,
		adaptiveMode: true,
	}
	if fc.enabled {
		fc.tokenBucket = make(chan struct{}, maxQPS)
		// 填充令牌桶
		for i := 0; i < maxQPS; i++ {
			fc.tokenBucket <- struct{}{}
		}
		// 定时补充令牌
		go fc.refillTokens()
	}
	return fc
}

// Wait 等待获取一个令牌（限流）
func (fc *FlowController) Wait() {
	if !fc.enabled {
		return
	}
	<-fc.tokenBucket
}

// TryWait 尝试获取令牌，非阻塞
func (fc *FlowController) TryWait() bool {
	if !fc.enabled {
		return true
	}
	select {
	case <-fc.tokenBucket:
		return true
	default:
		return false
	}
}

// SetQPS 动态调整QPS
func (fc *FlowController) SetQPS(qps int) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.currentQPS = qps
}

// GetQPS 获取当前QPS
func (fc *FlowController) GetQPS() int {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.currentQPS
}

// AdaptQPS 根据队列深度自适应调整QPS
func (fc *FlowController) AdaptQPS(queueUsagePct float64) {
	if !fc.adaptiveMode {
		return
	}
	fc.mu.Lock()
	defer fc.mu.Unlock()

	switch {
	case queueUsagePct > 80:
		// 队列快满了，大幅降速
		fc.currentQPS = max(fc.maxQPS/10, 10)
	case queueUsagePct > 60:
		// 队列偏满，降速
		fc.currentQPS = max(fc.maxQPS/4, 50)
	case queueUsagePct > 40:
		// 队列中等，适当降速
		fc.currentQPS = max(fc.maxQPS/2, 100)
	default:
		// 队列空闲，全速
		fc.currentQPS = fc.maxQPS
	}
}

// refillTokens 定时补充令牌
func (fc *FlowController) refillTokens() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for range ticker.C {
		fc.mu.Lock()
		qps := fc.currentQPS
		fc.mu.Unlock()

		// 补充令牌到当前QPS水平
		for i := 0; i < qps; i++ {
			select {
			case fc.tokenBucket <- struct{}{}:
			default:
				// 桶满了
				goto next
			}
		}
	next:
	}
}

// counter 原子计数器辅助
type counter struct {
	in       atomic.Int64
	out      atomic.Int64
	dropped  atomic.Int64
	lastIn   atomic.Int64
	lastOut  atomic.Int64
	lastTime atomic.Int64
}

func (c *counter) IncrIn()   { c.in.Add(1) }
func (c *counter) IncrOut()  { c.out.Add(1) }
func (c *counter) IncrDrop() { c.dropped.Add(1) }

func (c *counter) Rates() (rateIn, rateOut float64) {
	now := time.Now().UnixMilli()
	last := c.lastTime.Swap(now)
	if last == 0 {
		c.lastIn.Store(c.in.Load())
		c.lastOut.Store(c.out.Load())
		return 0, 0
	}

	elapsed := float64(now-last) / 1000.0
	if elapsed <= 0 {
		return 0, 0
	}

	curIn := c.in.Load()
	curOut := c.out.Load()
	prevIn := c.lastIn.Swap(curIn)
	prevOut := c.lastOut.Swap(curOut)

	rateIn = float64(curIn-prevIn) / elapsed
	rateOut = float64(curOut-prevOut) / elapsed
	return
}

// Sender 流量镜像发送器
type Sender struct {
	serverURL string
	token     string
	client    *http.Client
	logger    *slog.Logger
	queue     chan *model.MirrorRequest
	wg        sync.WaitGroup
	batchSize int
	counter   counter
	capacity  int
}

// NewSender 创建镜像发送器
func NewSender(serverURL, token string, logger *slog.Logger) *Sender {
	capacity := 10000
	s := &Sender{
		serverURL: serverURL,
		token:     token,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger:    logger,
		queue:     make(chan *model.MirrorRequest, capacity),
		batchSize: 50,
		capacity:  capacity,
	}

	// 启动发送worker
	for i := 0; i < 4; i++ {
		s.wg.Add(1)
		go s.worker()
	}

	return s
}

// Send 异步发送镜像流量
func (s *Sender) Send(r *http.Request, body []byte) {
	req := &model.MirrorRequest{
		Method:    r.Method,
		URL:       r.URL.String(),
		Headers:   r.Header,
		Body:      body,
		Timestamp: time.Now().Unix(),
		Protocol:  "http",
	}

	s.counter.IncrIn()
	select {
	case s.queue <- req:
	default:
		s.counter.IncrDrop()
		s.logger.Warn("mirror queue full, dropping request", "url", req.URL,
			"queue_len", len(s.queue), "queue_cap", s.capacity,
			"total_dropped", s.counter.dropped.Load())
	}
}

// SendRaw 发送原始数据帧（WebSocket等）
func (s *Sender) SendRaw(url string, direction string, data []byte) {
	method := "WS_FRAME"
	if direction == "response" {
		method = "WS_FRAME_RESP"
	}

	req := &model.MirrorRequest{
		Method:    method,
		URL:       url,
		Body:      data,
		Timestamp: time.Now().Unix(),
		Protocol:  "websocket",
	}

	s.counter.IncrIn()
	select {
	case s.queue <- req:
	default:
		s.counter.IncrDrop()
		s.logger.Warn("mirror queue full, dropping ws frame", "url", url)
	}
}

// Stop 停止发送器
func (s *Sender) Stop() {
	close(s.queue)
	s.wg.Wait()
}

// Stats 获取队列统计
func (s *Sender) Stats() QueueStats {
	rateIn, rateOut := s.counter.Rates()
	usagePct := float64(len(s.queue)) / float64(s.capacity) * 100

	return QueueStats{
		Name:         "sender",
		Length:       len(s.queue),
		Capacity:     s.capacity,
		UsagePct:     usagePct,
		TotalIn:      s.counter.in.Load(),
		TotalOut:     s.counter.out.Load(),
		TotalDropped: s.counter.dropped.Load(),
		RateIn:       rateIn,
		RateOut:      rateOut,
	}
}

// worker 从队列消费并发送到远端
func (s *Sender) worker() {
	defer s.wg.Done()

	batch := make([]*model.MirrorRequest, 0, s.batchSize)
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()

	for {
		select {
		case req, ok := <-s.queue:
			if !ok {
				if len(batch) > 0 {
					s.sendBatch(batch)
				}
				return
			}
			s.counter.IncrOut()
			batch = append(batch, req)
			if len(batch) >= s.batchSize {
				s.sendBatch(batch)
				batch = make([]*model.MirrorRequest, 0, s.batchSize)
				timer.Reset(2 * time.Second)
			}
		case <-timer.C:
			if len(batch) > 0 {
				s.sendBatch(batch)
				batch = make([]*model.MirrorRequest, 0, s.batchSize)
			}
			timer.Reset(2 * time.Second)
		}
	}
}

// sendBatch 批量发送到远端Server
func (s *Sender) sendBatch(batch []*model.MirrorRequest) {
	data, err := json.Marshal(batch)
	if err != nil {
		s.logger.Error("marshal batch failed", "error", err)
		return
	}

	endpoint := fmt.Sprintf("%s/api/v1/mirror/batch", s.serverURL)
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(data))
	if err != nil {
		s.logger.Error("create mirror request failed", "error", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Token", s.token)

	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Error("send mirror batch failed", "error", err, "count", len(batch))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		s.logger.Error("mirror batch rejected", "status", resp.StatusCode, "body", string(body))
		return
	}

	s.logger.Debug("mirror batch sent", "count", len(batch))
}

// Receiver 远端Server的流量接收器
type Receiver struct {
	logger    *slog.Logger
	onRequest func(*model.MirrorRequest)
	counter   counter
	capacity  int
	flowCtrl  *FlowController // 流速控制器：控制发送到XRay的速率
}

// NewReceiver 创建流量接收器
func NewReceiver(logger *slog.Logger, maxQPS int) *Receiver {
	capacity := 50000
	return &Receiver{
		logger:   logger,
		capacity: capacity,
		flowCtrl: NewFlowController(maxQPS),
	}
}

// SetOnRequest 设置请求回调
func (r *Receiver) SetOnRequest(fn func(*model.MirrorRequest)) {
	r.onRequest = fn
}

// HandleBatch 处理批量镜像请求（HTTP handler调用）
func (r *Receiver) HandleBatch(requests []*model.MirrorRequest) {
	for _, req := range requests {
		r.counter.IncrIn()

		pending := r.counter.in.Load() - r.counter.out.Load() - r.counter.dropped.Load()
		if pending < 0 {
			pending = 0
		}
		usagePct := float64(pending) / float64(r.capacity) * 100
		r.flowCtrl.AdaptQPS(usagePct)

		if !r.flowCtrl.TryWait() {
			r.counter.IncrDrop()
			continue
		}

		if pending > int64(r.capacity) {
			r.counter.IncrDrop()
			r.logger.Warn("xray pipe full, dropping request", "url", req.URL,
				"pipe_len", pending, "total_dropped", r.counter.dropped.Load())
			continue
		}

		if r.onRequest != nil {
			r.onRequest(req)
			r.counter.IncrOut()
		} else {
			r.counter.IncrDrop()
		}
	}
}

// XRayPipe 获取XRay管道（供XRay管理器消费）
func (r *Receiver) XRayPipe() <-chan *model.MirrorRequest {
	return nil
}

// Stats 获取接收器队列统计
func (r *Receiver) Stats() QueueStats {
	rateIn, rateOut := r.counter.Rates()
	length := int(r.counter.in.Load() - r.counter.out.Load() - r.counter.dropped.Load())
	if length < 0 {
		length = 0
	}
	if length > r.capacity {
		length = r.capacity
	}
	usagePct := float64(length) / float64(r.capacity) * 100

	return QueueStats{
		Name:         "xray_pipe",
		Length:       length,
		Capacity:     r.capacity,
		UsagePct:     usagePct,
		TotalIn:      r.counter.in.Load(),
		TotalOut:     r.counter.out.Load(),
		TotalDropped: r.counter.dropped.Load(),
		RateIn:       rateIn,
		RateOut:      rateOut,
	}
}

// FlowStats 获取流速控制状态
func (r *Receiver) FlowStats() map[string]interface{} {
	return map[string]interface{}{
		"enabled":     r.flowCtrl.enabled,
		"current_qps": r.flowCtrl.GetQPS(),
		"max_qps":     r.flowCtrl.maxQPS,
		"adaptive":    r.flowCtrl.adaptiveMode,
	}
}

// SetMaxQPS 动态设置最大QPS
func (r *Receiver) SetMaxQPS(qps int) {
	r.flowCtrl.SetQPS(qps)
}

// ValidateToken 验证请求Token
func ValidateToken(serverURL, token string) bool {
	u, _ := url.Parse(serverURL)
	u.Path = "/api/v1/ping"

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-Token", token)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
