package config

import (
	"database/sql"
	"log"

	_ "github.com/denisenkom/go-mssqldb"
)

var DB *sql.DB

func InitDB() {
	var err error
	// 修改为你的SQL Server连接信息
	connString := "server=localhost;user id=sa;password=yao040225;database=signature_sys;encrypt=disable"
	DB, err = sql.Open("sqlserver", connString)
	if err != nil {
		log.Fatal("数据库连接失败:", err)
	}
	if err = DB.Ping(); err != nil {
		log.Fatal("数据库不可用:", err)
	}
	log.Println("数据库连接成功")
}
