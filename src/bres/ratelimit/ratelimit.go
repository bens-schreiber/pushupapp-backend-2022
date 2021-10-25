package ratelimit

import (
	"github.com/gin-gonic/gin"
	"log"
	"sync"
	"time"
)

const (
	VISITOR_LIFETIME = 10 // in seconds
	VISITOR_MAX_REQS = 5
)

type Visitor struct {
	Reqs        int
	Exp         time.Time
	RateLimited bool
}

func (v *Visitor) Expired() bool {
	return v.Exp.Before(time.Now())
}

func (v *Visitor) Increment() {
	v.Reqs++
}

// Increment the expiration value by 1
func (v *Visitor) IncrementExp() {
	v.SecondsLimited++
	v.Exp = v.Exp.Add(time.Second)
}

func (v *Visitor) RateLimit() {
	v.RateLimited = true
	v.Exp = v.Exp.Add(time.Second * VISITOR_LIFETIME)
}

func (v *Visitor) Reset() {
	v.Reqs = 0
	v.Exp = time.Now().Add(time.Second * VISITOR_LIFETIME)
	v.RateLimited = false
}

type IPRateLimitMap struct {
	IPVisitor map[string]*Visitor
	Mu        *sync.Mutex
}

func (i *IPRateLimitMap) GetVisitor(ip string) *Visitor {
	return i.IPVisitor[ip]
}

func (i *IPRateLimitMap) AddVisitor(ip string) {
	log.Println("Adding visitor: " + ip)
	i.IPVisitor[ip] = &Visitor{
		Exp:  time.Now().Add(time.Second * VISITOR_LIFETIME),
		Reqs: 1,
	}
}

func (i *IPRateLimitMap) VisitorExists(ip string) bool {
	_, ok := i.IPVisitor[ip]
	return ok

}

func (i *IPRateLimitMap) DeleteVisitor(ip string) {
	delete(i.IPVisitor, ip)
}

var limit *IPRateLimitMap

func IPRateLimiter(c *gin.Context) {
	limit.Mu.Lock()
	defer limit.Mu.Unlock()

	if limit.VisitorExists(c.ClientIP()) {


		v := limit.GetVisitor(c.ClientIP())
		if v.Expired() {
			// Renew visitor
			v.Reset()
			return
		}

		if v.RateLimited {

			// Increment the ratelimit expiration date by 1 second
			v.IncrementExp()

			// STATUS: 429 RateLimited
			c.AbortWithStatus(429)

			return
		}

		// Ratelimit the user if they have
		// surpassed the allowed requests in the time period
		if v.Reqs > VISITOR_MAX_REQS {

			// Set RateLimited boolean
			// Use exp date as throttle time
			v.RateLimit()

			// STATUS: 429 RateLimited
			c.AbortWithStatus(429)
			return
		}

		v.Increment()
		return

	}
	limit.AddVisitor(c.ClientIP())
	return
}

func cleanVisitors() {
	for {
		time.Sleep(time.Minute)
		limit.Mu.Lock()
		for k, v := range limit.IPVisitor {
			if v.Expired() {
				limit.DeleteVisitor(k)
				log.Println("Visitor : " + k + " deleted.")
			}

		}
		limit.Mu.Unlock()
	}

}

func Init() {
	limit = &IPRateLimitMap{
		IPVisitor: make(map[string]*Visitor),
		Mu:        &sync.Mutex{},
	}

	go cleanVisitors()
}
