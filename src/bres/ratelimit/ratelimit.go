// Contains gin middleware to ratelimit via IPs
// Responds with HTTP 429 if a visitor exceeds VISITOR_MAX_REQs
// Must call ratecache.Init() to initialize the maps
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

type visitor struct {
	Reqs        int
	Exp         time.Time
	RateLimited bool
}

func (v *visitor) expired() bool {
        return v.Exp.Before(time.Now())
    }

func (v *visitor) increment() {
    v.Reqs++
}

// Increment the expiration value by 1
func (v *visitor) incrementExp() {
	v.Exp = v.Exp.Add(time.Second)
}

// Flip the ratelimit bool to signify that the visitor exp
// is now the time the user should be ratelimited
func (v *visitor) rateLimit() {
	v.RateLimited = true
	v.Exp = v.Exp.Add(time.Second * VISITOR_LIFETIME)
}

// Set to default values for all of a visitors properties
func (v *visitor) reset() {
	log.Println("Reseting a visitor")
	v.Reqs = 0
	v.Exp = time.Now().Add(time.Second * VISITOR_LIFETIME)
	v.RateLimited = false
}

// Maps a IP string to a visitor struct
// Field Mu for handling concurrency
type IPCache struct {
	Visitors map[string]*visitor
	Mu        *sync.Mutex
}

// Return a visitor via searching for their IP
func (i *IPCache) getVisitor(ip string) *visitor {
	return i.Visitors[ip]
}

// Update the map with a new ip,visitor
func (i *IPCache) addVisitor(ip string) {
	log.Println("Adding visitor: " + ip)
	i.Visitors[ip] = &visitor{
		Exp:  time.Now().Add(time.Second * VISITOR_LIFETIME),
		Reqs: 1,
	}
}

func (i *IPCache) visitorExists(ip string) bool {
	_, ok := i.Visitors[ip]
	return ok

}

// Remove a map entry
func (i *IPCache) deleteVisitor(ip string) {
	delete(i.Visitors, ip)
}

var cache *IPCache

// Main func, middleware for gin engine (concurrency safe)
// Runs on every API call
// Add IP to map if nonexistant
// Ratelimit user on VISITOR_MAX_REQ exceeded
func IPRateLimiter(c *gin.Context) {
	cache.Mu.Lock()
	defer cache.Mu.Unlock()

	if cache.visitorExists(c.ClientIP()) {

		v := cache.getVisitor(c.ClientIP())
		if v.expired() {
			// Renew visitor
			v.reset()
			return
		}

		if v.RateLimited {

			// Increment the ratelimit expiration date by 1 second
			v.incrementExp()

			// STATUS: 429 RateLimited
			c.AbortWithStatus(429)

			return
		}

		// Ratelimit the user if they have
		// surpassed the allowed requests in the time period
		if v.Reqs > VISITOR_MAX_REQS {

			// Set RateLimited boolean
			// Use exp date as throttle time
			v.rateLimit()

			// STATUS: 429 RateLimited
			c.AbortWithStatus(429)
			return
		}

		v.increment()
		return

	}
	cache.addVisitor(c.ClientIP())
	return
}

// Goroutine to periodically clean visitor maps
// Lock map while cleaning
func cleanvisitors() {
	for {
		time.Sleep(time.Minute)
		cache.Mu.Lock()
		for k, v := range cache.Visitors {
			if v.expired() {
				cache.deleteVisitor(k)
				log.Println("visitor : " + k + " deleted.")
			}

		}
		cache.Mu.Unlock()
	}

}

// Initialize the ratelimit map in memory
func Init() {
	log.Println("Initializing ratelimit maps")
	cache = &IPCache{
		Visitors: make(map[string]*visitor),
		Mu:        &sync.Mutex{},
	}

	go cleanvisitors()
}
