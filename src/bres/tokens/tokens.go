package tokens

import (
	"errors"
	"github.com/google/uuid"
	"log"
	"sync"
	"time"
)

type Client struct {
	IP   string
	User string
	Exp  time.Time
}

func (c *Client) Expired() bool {
	return c.Exp.Before(time.Now())
}

// Struct that maintains a necessary maps for managing APITokens
type APITokens struct {
	TokenClient map[string]*Client
	UserToken   map[string]string
	Mu          *sync.Mutex
}

func (a *APITokens) GetClient(token string) (*Client, error) {
	if v, ok := a.TokenClient[token]; ok {
		return v, nil
	}
	err := errors.New("APITokens: user not found")
	return nil, err

}

func (a *APITokens) TokenExists(token string) bool {
	_, ok := a.TokenClient[token]
	return ok
}

func (a *APITokens) DeleteUser(token string) error {
	c, err := a.GetClient(token)
	if err != nil {
		return err
	}

	delete(a.TokenClient, token)
	delete(a.UserToken, c.User)
	return err
}

func (a *APITokens) updateMap(ip string, username string, token string) {
	// Add a new client to the maps with an exp of 6 hours
	// from current time
	a.TokenClient[token] = &Client{
		IP:   ip,
		User: username,
		Exp:  time.Now().Add(time.Hour * 6),
	}

	a.UserToken[username] = token
}

func AddClient(ip string, username string) string {
	apitokens.Mu.Lock()
	defer apitokens.Mu.Unlock()

	// Create a random uid
	uid := uuid.New().String()

	if _, err := apitokens.GetClient(username); err == nil {
		apitokens.DeleteUser(username)
		log.Println("Refreshing a token")
	}

	apitokens.updateMap(ip, username, uid)
	return uid
}

var apitokens *APITokens

func GetAPITokens() *APITokens {
	return apitokens
}

func Init() {

	log.Println("Initializing token maps")

	apitokens = &APITokens{
		TokenClient: make(map[string]*Client),
		UserToken:   make(map[string]string),
		Mu:          &sync.Mutex{},
	}

	go cleanTokens()
}

func cleanTokens() {
	for {
		apitokens.Mu.Lock()
		for _, v := range apitokens.TokenClient {
			if v.Expired() {
				log.Println("Removing a token: " + v.User)
				apitokens.DeleteUser(v.User)
			}
		}
		apitokens.Mu.Unlock()
	}
}
