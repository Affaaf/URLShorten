package main

import (
	"Go_CRUD.com/m/initializers"
	"Go_CRUD.com/m/models"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
}

func main() {

	initializers.DB.AutoMigrate(&models.URLShorten{}, &models.User{})

}
