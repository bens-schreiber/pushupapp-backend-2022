// Contains functions to store API tokens linked to user accounts in memory
// Generates a UID  on AddClient()
// Tokens expire after 6 hour
// Must call tokens.Init() to initalize maps
package tokens

import (
	"errors"
	"github.com/google/uuid"
	"log"
	"sync"
	"time"
)

type client struct {
	IP   string
	User string
	Exp  time.Time
}

func (c *client) Expired() bool {
	return c.Exp.Before(time.Now())
}

// Struct that maintains a necessary maps for managing TokenCache
type TokenCache struct {
	TokenClient map[string]*client
	UserToken   map[string]string
	Mu          *sync.Mutex
}

var cache *TokenCache

func GetClient(token string) (client, error) {
    cache.Mu.Lock()
    defer cache.Mu.Unlock()

    v := cache.TokenClient[token]
	if v, ok := cache.TokenClient[token]; ok {
		return *v, nil
	}
	err := errors.New("user not found")
	return *v, err

}

func TokenExists(token string) bool {
    cache.Mu.Lock()
    defer cache.Mu.Unlock()

	_, ok := cache.TokenClient[token]
	return ok
}

func DeleteUser(token string) error {
    cache.Mu.Lock()
    defer cache.Mu.Unlock()
    
	c, err := GetClient(token)
	if err != nil {
		return err
	}

	delete(cache.TokenClient, token)
	delete(cache.UserToken, c.User)
	return err
}

func updateMap(ip string, username string, token string) {
    cache.Mu.Lock()
    defer cache.Mu.Unlock()
    

	// Add a new client to the maps with an exp of 6 hours
	// from current time
	cache.TokenClient[token] = &client{
		IP:   ip,
		User: username,
		Exp:  time.Now().Add(time.Hour * 6),
	}

	cache.UserToken[username] = token
}

func AddClient(ip string, username string) string {
	cache.Mu.Lock()
	defer cache.Mu.Unlock()

	// Create a random uid
	uid := uuid.New().String()

	if _, err := GetClient(username); err == nil {
		DeleteUser(username)
		log.Println("Refreshing a token")
	}

	updateMap(ip, username, uid)
	return uid
}


func Init() {

	log.Println("Initializing token maps")

	cache = &TokenCache{
		TokenClient: make(map[string]*client),
		UserToken:   make(map[string]string),
		Mu:          &sync.Mutex{},
	}

	go cleanTokens()
}

// Goroutine to  clean tokens every 10 min 
func cleanTokens() {
	for {
		time.Sleep(time.Minute * 10)
		cache.Mu.Lock()
		for _, v := range cache.TokenClient {
			if v.Expired() {
				log.Println("Removing a token: " + v.User)
				DeleteUser(v.User)
			}
		}
		cache.Mu.Unlock()
	}
}
