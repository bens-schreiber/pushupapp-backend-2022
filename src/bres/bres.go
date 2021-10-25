// Rest Endpoint Security helper function package
package bres

import (
	"benschreiber.com/purestserver/src/bres/ratelimit"
	"benschreiber.com/purestserver/src/bres/tokens"
	"benschreiber.com/purestserver/src/bsql"
	"database/sql"
	"github.com/gin-gonic/gin"
	"log"
	"regexp"
)

// Initialize maps in memory
func Init() {

	configLogger()

	tokens.Init()

	ratelimit.Init()
}

// Insert a new token into memory
func AddClient(ip string, username string) string {
	return tokens.AddClient(ip, username)
}

// Checks context for specified headers
// STATUS: 400 Bad Request on missing header
func ValidateHeaders(c *gin.Context, args ...string) bool {
	for _, v := range args {
		if c.GetHeader(v) == "" {
			log.Println("invalid or missing headers")
			c.AbortWithStatus(400)
			return false
		}
	}
	return true
}

// General authentication validation
// Validate API Tokens
func ValidateAuthentication(c *gin.Context) (bool, error) {

	var err error

	// Validate all headers are present in request
	if !ValidateHeaders(c, "Token", "Username") {
		return false, err
	}

	// Grab auth fields
	token := c.GetHeader("Token")
	username := c.GetHeader("Username")

	tokens.GetAPITokens().Mu.Lock()
	defer tokens.GetAPITokens().Mu.Unlock()

	// Validate user is in allowed characters
	// STATUS: 400 Bad Request on illegal characters
	if ok, err := ValidateUserPassRegex(c, username, ""); !ok {
		return !ok, err
	}

	// Verify the user exists
	// STATUS: 404 Not Found on non-existant user
	if ok, err := bsql.UserExists(username); !ok {
		c.AbortWithStatus(400)
		return ok, err
	}

	// Check if api token exists
	// STATUS: 401 Unauthorized on invalid token
	if !tokens.GetAPITokens().TokenExists(token) {
		log.Println("invalid token")
		c.AbortWithStatus(401)
		return false, err
	}

	// Validate token field
	// STATUS: 401 Unauthorized on invalid token
	client, _ := tokens.GetAPITokens().GetClient(token)
	if client.Expired() ||
		client.User != username ||
		client.IP != c.ClientIP() {

		log.Println("compromised, expired or invalid")
		// Remove invalidated Token
		tokens.GetAPITokens().DeleteUser(token)
		c.AbortWithStatus(401)
		return false, err

	}
	return true, err
}

// Check if user is capable of making a coin request
func ValidateCoinRequest(c *gin.Context, user string, id string) (bool, error) {
	err := bsql.SelectCoinHolder(user, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
	}
	return true, err
}

func ValidateUserPassRegex(c *gin.Context, username string, password string) (bool, error) {

	// Handle a bad username that contains illegal characters
	if regex, err := regexp.Compile("[^A-Za-z0-9]+"); regex.MatchString(username) {
		log.Println("username does not follow guidelines")
		c.AbortWithStatus(400)
		return false, err
	}

	//See if password contains any whitespaces
	if password != "" {
		if regex, err := regexp.Compile("\\s+"); regex.MatchString(password) {
			log.Println("password does not follow guidelines")
			c.AbortWithStatus(400)
			return false, err
		}
	}

	return true, nil
}

func configLogger() {
	log.SetPrefix("[bres] ")
	log.SetFlags(log.Lmsgprefix)
}
