package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"around/model"
	"around/service"

	jwt "github.com/form3tech-oss/jwt-go"
)

var mySigningKey = []byte("secret") // need to change to a secure place if the project is face to online user

func signinHandler(w http.ResponseWriter, r *http.Request) { // using the reference of request is faster
	// than make a copy of request(pass by value)
	fmt.Println("Received one signin request")
	decoder := json.NewDecoder(r.Body)
	var user model.User

	if err := decoder.Decode(&user); err != nil {
		http.Error(w, "Failed to decode user data from request body", http.StatusBadRequest)
		return
	}

	exists, err := service.CheckUser(user.Username, user.Password)
	if err != nil {
		http.Error(w, "Failed to read user from backend", http.StatusInternalServerError)
		return
	}

	if !exists {
		http.Error(w, "User doesn't exists", http.StatusUnauthorized) // return 401
		return
	}

	// claims == payload
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	})
	tokenString, err := token.SignedString(mySigningKey) // jwt encode way
	if err != nil {
		http.Error(w, "Failed to generate token ", http.StatusInternalServerError)
		fmt.Printf("Failed to generate token %v\n", err)
		return
	}
	w.Write([]byte(tokenString))

}
func signupHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received one signup request")
	w.Header().Set("Content-Type", "text/plain")

	// read user
	decoder := json.NewDecoder(r.Body)
	var user model.User
	if err := decoder.Decode(&user); err != nil {
		http.Error(w, "Cannot decode user data from client", http.StatusBadRequest)
		fmt.Printf("Cannot decode user data from client %v\n", err)
		return
	}
	// authenity check
	if user.Username == "" || user.Password == "" || regexp.MustCompile(`^[a-z0-9]$`).MatchString(user.Username) { // restriction for user name

		http.Error(w, "Invalid username or password", http.StatusBadRequest)
		fmt.Printf("Invalid username or password\n")
		return
	}

	success, err := service.AddUser(&user)
	if err != nil {
		http.Error(w, "Failed to save user to Elasticsearch", http.StatusInternalServerError)
		fmt.Printf("Failed to save user to Elasticsearch %v\n", err)
		return
	}

	if !success {
		http.Error(w, "User already exists", http.StatusBadRequest)
		fmt.Println("User already exists")
		return
	}
	fmt.Printf("User added successfully: %s.\n", user.Username)
}
