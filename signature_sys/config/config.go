// 数据库连接配置与初始化
// 负责初始化SQL Server数据库连接，供全局使用
package config

import (
	"database/sql"
	"log"

	_ "github.com/denisenkom/go-mssqldb"
)

// DB为全局数据库连接对象，供各模块直接使用
var DB *sql.DB

// InitDB 初始化数据库连接，程序启动时调用
// 连接失败或不可用时直接终止程序
func InitDB() {
	var err error
	connString := "server=localhost;user id=sa;password=yao040225;database=signature_sys;encrypt=disable"
	DB, err = sql.Open("sqlserver", connString)
	if err != nil {
		log.Fatal("数据库连接失败:", err)
	}
	// 检查数据库是否可用
	if err = DB.Ping(); err != nil {
		log.Fatal("数据库不可用:", err)
	}
	log.Println("数据库连接成功")
}
