package main

import (
	"benschreiber.com/purestserver/src/bres"
	"benschreiber.com/purestserver/src/bres/ratelimit"
	"benschreiber.com/purestserver/src/bsql"
	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
	"log"
)

func main() {

	log.SetPrefix("[main] ")
	log.SetFlags(log.Lmsgprefix)

	//Establish connection to local db
	if err := bsql.Establishconnection(); err != nil {
		log.Fatal(err)
	}

	//Establish token pool, establish ratelimit map
	bres.Init()

	//Define API endpoint
	router := gin.Default()
	router.Use(ratelimit.IPRateLimiter)

	// Client endpoints
	client := "/api/client/"
	router.POST(client+"login", loginClient)
	router.POST(client+"register", registerClient)

	// Group endpoints
	group := "/api/group/"
	router.GET(group+":user", getGroup)
	router.POST(group+"create", postGroup)
	router.POST(group+"join", postGroupMember)
	router.POST(group+"coin", postCoin)
	router.DELETE(group+"kick/:user", delGroupMember)
	router.DELETE(group+"disband", delGroup)

	//port 8080
	router.Run()
}

// METHOD: POST
// Generate API token in bres package
// Requires Username, Password headers
func loginClient(c *gin.Context) {

	// Validate headers exist
	// STATUS: 400 Bad Request on missing headers
	if !bres.ValidateHeaders(c, "Username", "Password") {
		return
	}

	//Grab headers
	user := c.GetHeader("Username")
	pass := c.GetHeader("Password")

	// Validate userpass in allowed characters
	// STATUS: 400 bad request on illegal characters
	ok, err := bres.ValidateUserPassRegex(c, user, pass)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		return
	}

	// STATUS: 404 on nonexistant user
	ok, err = bsql.UserExists(user)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		c.AbortWithStatus(404)
		return
	}

	// Validate the credentials the user gave
	// STATUS: 401 Unauthorized on invalid credentials
	ok, err = bsql.MatchUserPass(user, pass)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		c.AbortWithStatus(401)
		return
	}

	// Create the token in memory, return in JSON
	// STATUS: 201 Created
	c.JSON(201, gin.H{"token": bres.AddClient(c.ClientIP(), user)})
}

// METHOD: POST
// Insert a new user into the database
// Requires Username, Password headers
func registerClient(c *gin.Context) {

	// Validate headers exist
	// STATUS: 400 Bad Request on missing headers
	if !bres.ValidateHeaders(c, "Username", "Password") {
		return
	}

	// Grab headers
	user := c.GetHeader("Username")
	pass := c.GetHeader("Password")

	// Validate userpass in allowed characters
	// STATUS: 400 bad request on illegal characters
	ok, err := bres.ValidateUserPassRegex(c, user, pass)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		return
	}

	// Validate Username is unique
	// STATUS: 400 Bad Request on non unique user
	ok, err = bsql.UserExists(user)
	if err != nil {
		log.Fatal(err)
	}
	if ok {
		log.Println("user already exists")
		c.AbortWithStatus(400)
		return
	}

	// Add user to db
	if err = bsql.InsertNewUser(user, pass); err != nil {
		log.Fatal(err)
	}

	// STATUS: 201 Created
	c.Status(201)
}

// METHOD: GET
// Return all Group fields and Group Members
// Requires Username, Token headers; user param
func getGroup(c *gin.Context) {

	// Validate userpass and Token fields exis
	// STATUS: 401 Unauthorized on invalid token
	// STATUS: 400 Bad Request on missing header; illegal chars
	// STATUS: 404 on non-existant user
	ok, err := bres.ValidateAuthentication(c)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		return
	}

	// Grab user parameter
	user := c.Param("user")

	// Create return JSON
	// STATUS: 404 Not Found if user is not in a group
	group, ok, err := bsql.GetUserGroup(user)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		c.AbortWithStatus(404)
		return
	}

	// STATUS: 200 OK
	c.JSON(200, group)
}

// METHOD: POST
// Insert a new group into the database
// Requires Username, Token headers
func postGroup(c *gin.Context) {

	// Validate userpass and Token fields exis
	// STATUS: 401 Unauthorized on invalid token
	// STATUS: 400 Bad Request on missing header; illegal chars
	// STATUS: 404 on non-existant user
	ok, err := bres.ValidateAuthentication(c)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		return
	}

	// Grab user parameter
	user := c.GetHeader("Username")

	// STATUS 403 Forbidden if a user is already a group owner
	ok, err = bsql.GroupExists(user)
	if err != nil {
		log.Fatal(err)
	}
	if ok {
		c.AbortWithStatus(403)
		return
	}

	// Register new group
	if err = bsql.InsertNewGroup(user); err != nil {
		log.Fatal(err)
	}

	// STATUS: 200 OK
	c.Status(200)
}

// METHOD: POST
// Inserts user into a specified group
// Requires Username, Token, ID headers
func postGroupMember(c *gin.Context) {

	// Validate that ID is in the header
	// STATUS: 400 Bad Request on missing header
	ok := bres.ValidateHeaders(c, "ID")
	if !ok {
		return
	}

	// Validate userpass and Token fields exis
	// STATUS: 401 Unauthorized on invalid token
	// STATUS: 400 Bad Request on missing header; illegal chars
	// STATUS: 404 on non-existant user
	ok, err := bres.ValidateAuthentication(c)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		return
	}

	// Grab user and group id
	user := c.GetHeader("Username")
	id := c.GetHeader("ID")

	// STATUS: 404 Not Found on non-existant group
	ok, err = bsql.GroupExists(id)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		c.AbortWithStatus(404)
		return
	}

	// Err on non-unique entry ( user cannot be in same group twice)
	if err = bsql.InsertGroupMember(user, id); err != nil {
		if _, ok = err.(*mysql.MySQLError); !ok {
			log.Fatal(err)
		}
		if err.(*mysql.MySQLError).Number == 1062 {
			log.Println("User already in group they tried to join")
			c.AbortWithStatus(400)
			return
		}
	}

	// STATUS: 200, OK
	c.Status(200)

}

// METHOD: POST
// Updates group's coin
// Requires Username, Token, ID headers
func postCoin(c *gin.Context) {

	// Validate that ID is in the header
	// STATUS: 400 Bad Request on missing header
	ok := bres.ValidateHeaders(c, "ID")
	if !ok {
		return
	}

	// Validate userpass and Token fields exis
	// STATUS: 401 Unauthorized on invalid token
	// STATUS: 400 Bad Request on missing header; illegal chars
	// STATUS: 404 on non-existant user
	ok, err := bres.ValidateAuthentication(c)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		return
	}

	// Grab user and group id
	user := c.GetHeader("Username")
	id := c.GetHeader("ID")

	// STATUS: 404 Not Found on non-existant group
	ok, err = bsql.GroupExists(id)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		c.AbortWithStatus(404)
		return
	}

	// Validate the user is authorized to make a coin request
	// STATUS: 403 Forbidden on not high enough credentials
	ok, err = bres.ValidateCoinRequest(c, user, id)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		c.AbortWithStatus(403)
		return
	}

	if err1, err2 := bsql.UpdateCoin(user, id); err1 != nil || err2 != nil {
		log.Fatal(err1)
		log.Fatal(err2)
	}

	// STATUS: 201 Created
	c.Status(201)

}

// METHOD: DEL
// Delete a member from a group
// Requires Username, Token, ID headers, member param
func delGroupMember(c *gin.Context) {

	// Validate that ID is in the header
	// STATUS: 400 Bad Request on missing header
	ok := bres.ValidateHeaders(c, "ID")
	if !ok {
		return
	}

	// Validate userpass and Token fields exis
	// STATUS: 401 Unauthorized on invalid token
	// STATUS: 400 Bad Request on missing header; illegal chars
	// STATUS: 404 on non-existant user
	ok, err := bres.ValidateAuthentication(c)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		return
	}

	// Grab user and group id
	user := c.GetHeader("Username")
	id := c.GetHeader("ID")
	member := c.Param("user")

	// STATUS 404 Not found on non-existant member
	ok, err = bsql.UserExists(member)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		c.AbortWithStatus(404)
		return
	}

	// STATUS 404 Not Found on non-existant group
	ok, err = bsql.GroupExists(id)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		c.AbortWithStatus(404)
		return
	}

	// STATUS 404 User not found in group
	ok, err = bsql.UserInGroup(member, id)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		c.AbortWithStatus(404)
		return
	}

	// STATUS 403 Forbidden user not group creator
	ok, err = bsql.UserGroupCreator(user, id)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		c.AbortWithStatus(403)
		return
	}

	_, err = bsql.DeleteGroupMember(member, id)
	if err != nil {
		log.Fatal(err)
	}
	c.Status(200)

}

// METHOD: DEL
// Delete a group, and all its members
// Requires Username, Token, ID
func delGroup(c *gin.Context) {

	// Validate that ID is in the header
	// STATUS: 400 Bad Request on missing header
	ok := bres.ValidateHeaders(c, "ID")
	if !ok {
		return
	}

	// Validate userpass and Token fields exis
	// STATUS: 401 Unauthorized on invalid token
	// STATUS: 400 Bad Request on missing header; illegal chars
	// STATUS: 404 on non-existant user
	ok, err := bres.ValidateAuthentication(c)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		return
	}

	// Grab user and group id
	user := c.GetHeader("Username")
	id := c.GetHeader("ID")

	// STATUS 404 Not Found on non-existant group
	ok, err = bsql.GroupExists(id)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		c.AbortWithStatus(404)
		return
	}

	// STATUS 403 Forbidden user not group creator
	ok, err = bsql.UserGroupCreator(user, id)
	if err != nil {
		log.Fatal(err)
	}
	if !ok {
		c.AbortWithStatus(403)
		return
	}

	err = bsql.DeleteGroup(user)
	if err != nil {
		log.Fatal(err)
	}

	c.Status(200)

}
