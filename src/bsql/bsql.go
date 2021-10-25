// Helper function package for executing mysql queries
package bsql

import (
	"database/sql"
	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"log"
)

// SQL Database pointer
var db *sql.DB

// SQL: table _group
type Group struct {
	ID          string   `json:"id"`
	Token       int      `json:"coin"`
	Creator     string   `json:"creator"`
	TokenHolder string   `json:"coin_holder"`
	Members     []string `json:"members"`
}

// SQL: table group_member
type GroupMember struct {
	GroupID  string `json:"group_id"`
	Username string `json:"username"`
}

// SQL: table user
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func InsertNewUser(user string, pass string) error {
	_, err := insertUserQuery.Exec(user, pass)
	return err
}

func DeleteGroupMember(member string, id string) (sql.Result, error) {
	return deleteGroupMemberQuery.Exec(member, id)
}

func UserGroupCreator(user string, id string) (bool, error) {
	var group_id string
	err := selectGroupCreatorQuery.QueryRow(user, id).Scan(&group_id)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
	}
	return true, err
}

func GroupExists(id string) (bool, error) {

	// Return a value into group if group exists
	var group string
	err := selectGroupQuery.QueryRow(id).Scan(&group)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Println("group does not exist")
			return false, nil
		}
	}

	return true, err
}

func UserExists(user string) (bool, error) {

	// Return a value into username if the user exists
	var username string
	err := selectUserQuery.QueryRow(user).Scan(&username)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
	}

	return true, err
}

func MatchUserPass(user string, pass string) (bool, error) {
	var username string
	err := selectUserPassQuery.QueryRow(user, pass).Scan(&username)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Println("Credentials invalid")
			return false, nil
		}
	}

	return true, err
}

func GetUserGroup(user string) (*Group, bool, error) {
	var group Group

	err := selectUserGroupsQuery.QueryRow(user).Scan(
		&group.ID,
		&group.Token,
		&group.Creator,
		&group.TokenHolder)

	if err != nil {
		if err == sql.ErrNoRows {
			log.Println("group not found")
			return &group, false, nil
		}
	}

	rows, err := selectGroupMembersQuery.Query(group.ID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	for rows.Next() {
		var username string
		rows.Scan(&username)
		group.Members = append(group.Members, username)
	}

	return &group, true, err
}

func InsertGroupMember(user string, id string) error {
	_, err := insertGroupMemberQuery.Exec(id, user)
	return err
}

func InsertNewGroup(user string) error {

	var err error

	// group id
	id := uuid.New().String()
	tokenDefaultValue := 1

	_, err = insertGroupQuery.Exec(id, tokenDefaultValue, user, user)
	if err != nil {
		return err
	}

	if err = InsertGroupMember(user, id); err != nil {
		return err
	}

	return err
}

func SelectCoinHolder(user string, id string) error {
	var username string
	return selectCoinHolderQuery.QueryRow(user, id).Scan(&username)
}

func UpdateCoin(user string, id string) (error, error) {
	_, err1 := updateCoinQuery.Exec(id, user)
	_, err2 := updateCoinHolderQuery.Exec(id, id)
	return err1, err2
}

func UserInGroup(user string, id string) (bool, error) {
	var username string
	err := selectGroupFromUserQuery.QueryRow(id, user).Scan(&username)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
	}
	return true, err

}

func DeleteGroup(user string) error {
	_, err := deleteGroupQuery.Exec(user)
	return err

}

func Establishconnection() error {
	var err error

	cfg := mysql.Config{
		User:                 "root",
		Passwd:               "root",
		Net:                  "tcp",
		Addr:                 "127.0.0.1:3306",
		DBName:               "puapp",
		AllowNativePasswords: true,
	}

	db, err = sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return err
	}

	if err = db.Ping(); err != nil {
		return err
	}

	if err = setupPrepStates(); err != nil {
		return err
	}
	configLogger()
	log.Println("Connected to Database!")

	return err
}

var (
	insertUserQuery,
	selectUserQuery,
	selectUserPassQuery,
	selectUserGroupsQuery,
	selectGroupMembersQuery,
	insertGroupQuery,
	insertGroupMemberQuery,
	selectCoinHolderQuery,
	updateCoinQuery,
	updateCoinHolderQuery,
	selectGroupQuery,
	selectGroupCreatorQuery,
	selectGroupFromUserQuery,
	deleteGroupQuery,
	deleteGroupMemberQuery *sql.Stmt
)

//Setup all prepared statements
func setupPrepStates() error {
	var err error

	insertUserQuery, err = db.Prepare("insert into user(username, password) values (?, SHA(?))")
	if err != nil {
		return err
	}

	selectUserQuery, err = db.Prepare("select username from user where username=?")
	if err != nil {
		return err
	}

	selectUserPassQuery, err = db.Prepare("select username from user where username=? and password=SHA(?)")
	if err != nil {
		return err
	}

	selectUserGroupsQuery, err = db.Prepare("select * from _group where _group.id=(select group_id from group_member where username=?)")
	if err != nil {
		return err
	}

	selectGroupMembersQuery, err = db.Prepare("select username from group_member where group_id=?")
	if err != nil {
		return err
	}

	insertGroupQuery, err = db.Prepare("insert into _group(id, coin, creator, coin_holder) values (?, ?, ?, ?)")
	if err != nil {
		return err
	}

	insertGroupMemberQuery, err = db.Prepare("insert into group_member(group_id, username) values (?, ?)")
	if err != nil {
		return err
	}

	selectCoinHolderQuery, err = db.Prepare("select coin_holder from _group where coin_holder=? and id=?")
	if err != nil {
		return err
	}

	updateCoinQuery, err = db.Prepare("update _group set _group.coin = (_group.coin + 1) where id=? and coin_holder=?")
	if err != nil {
		return err
	}

	updateCoinHolderQuery, err = db.Prepare("update _group set coin_holder=(select username from group_member where group_id=? order by rand() limit 1) where id=?")
	if err != nil {
		return err
	}

	selectGroupQuery, err = db.Prepare("select id from _group where _group.id=?")
	if err != nil {
		return err
	}

	selectGroupCreatorQuery, err = db.Prepare("select id from _group where creator=? and id=?")
	if err != nil {
		return err
	}

	selectGroupFromUserQuery, err = db.Prepare("select username from group_member where group_id=? and username=?")
	if err != nil {
		return err
	}

	deleteGroupMemberQuery, err = db.Prepare("delete from group_member where username=? and group_id=?")
	if err != nil {
		return err
	}

	deleteGroupQuery, err = db.Prepare("delete from _group where creator=?")
	if err != nil {
		return err
	}

	return err
}

func configLogger() {
	log.SetFlags(log.Lmsgprefix)
	log.SetPrefix("[bsql] ")
}
