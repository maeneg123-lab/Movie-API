package main

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "net/http"
    "strconv"
    "time"
    "os"
    "log"
    "context"
    "strings"
    "github.com/golang-jwt/jwt/v5"
    "golang.org/x/crypto/bcrypt"


    _ "github.com/lib/pq"
)

var jwtSecret = []byte("твой_секретный_ключ_для_jwt")

func generateToken(userID int) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "user_id": userID,
        "exp":     time.Now().Add(time.Hour * 24).Unix(),
    })
    return token.SignedString(jwtSecret)
}


type Movies struct{
  db *sql.DB
}

func NewServer() *Movies {
    // Сначала пробуем взять строку из окружения
    connStr := os.Getenv("DATABASE_URL")
    // Если её нет — используем локальную для разработки
    if connStr == "" {
        connStr = "user=postgres password=36863686 dbname=work_db sslmode=disable"
    }

    db, err := sql.Open("postgres", connStr)
    if err != nil {
        log.Fatal(err)
    }
    return &Movies{db: db}
}

func (m *Movies) saveBooks(title string, year int64, rating float64, userID int) error {
    _, err := m.db.Exec(
        "INSERT INTO movies (title, year, rating, user_id) VALUES ($1, $2, $3, $4)",
        title, year, rating, userID,
    )
    return err
}


func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        tokenString := r.Header.Get("Authorization")
        if tokenString == "" {
            http.Error(w, "Токен не предоставлен", http.StatusUnauthorized)
            return
        }

        // Убираем "Bearer " из строки
        tokenString = strings.TrimPrefix(tokenString, "Bearer ")

        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("неверный метод подписи")
            }
            return jwtSecret, nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Неверный токен", http.StatusUnauthorized)
            return
        }

        // Извлекаем user_id из токена и добавляем в контекст запроса
        if claims, ok := token.Claims.(jwt.MapClaims); ok {
            userID := int(claims["user_id"].(float64))
            r = r.WithContext(context.WithValue(r.Context(), "user_id", userID))
        }

        next(w, r)
    }
}

func (m *Movies) new_movie(w http.ResponseWriter, r *http.Request){
    userID, ok := r.Context().Value("user_id").(int)
    if !ok {
        http.Error(w, "User not authorized", http.StatusUnauthorized)
        return
    }
    value := r.URL.Query()

    title := value.Get("title")
    yearstr:= value.Get("year")
    ratingstr := value.Get("rating")

    year, err := strconv.ParseInt(yearstr, 10, 64)
    if err!=nil{
        fmt.Fprintf(w, "year not int")
        return
    }

    rating, err := strconv.ParseFloat(ratingstr, 64)
    if err!= nil{
        fmt.Fprintf(w, "rating not float64")
    }

    err = m.saveBooks(title, year, rating, userID)
    if err!=nil{
        fmt.Fprintf(w, "error on save: %v", err)
    }
    fmt.Fprintf(w, "success")
}


func (m *Movies) register(w http.ResponseWriter, r *http.Request) {
    username := r.URL.Query().Get("username")
    password := r.URL.Query().Get("password")

    if username == "" || password == "" {
        http.Error(w, "Username and password are required", http.StatusBadRequest)
        return
    }

    // Хешируем пароль
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        http.Error(w, "Error hashing password", http.StatusInternalServerError)
        return
    }

    // Сохраняем в БД
    _, err = m.db.Exec("INSERT INTO users1 (username, password) VALUES ($1, $2)", username, hashedPassword)
    if err != nil {
        http.Error(w, "Username already exists", http.StatusConflict)
        return
    }

    fmt.Fprintf(w, "User registered successfully")
}

func (m *Movies) login(w http.ResponseWriter, r *http.Request) {
    username := r.URL.Query().Get("username")
    password := r.URL.Query().Get("password")

    if username == "" || password == "" {
        http.Error(w, "Username and password are required", http.StatusBadRequest)
        return
    }

    // Ищем пользователя в БД
    var userID int
    var hashedPassword string
    err := m.db.QueryRow("SELECT id, password FROM users1 WHERE username=$1", username).Scan(&userID, &hashedPassword)
    if err != nil {
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    // Проверяем пароль
    err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
    if err != nil {
        http.Error(w, "Invalid username or password", http.StatusUnauthorized)
        return
    }

    // Генерируем JWT-токен
    token, err := generateToken(userID)
    if err != nil {
        http.Error(w, "Error generating token", http.StatusInternalServerError)
        return
    }

    // Отправляем токен в ответе
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func (m *Movies) get_movie(w http.ResponseWriter, r *http.Request){
   userID, ok := r.Context().Value("user_id").(int)
  if !ok {
      http.Error(w, "User not authorized", http.StatusUnauthorized)
      return
  }
  rows, err:= m.db.Query(`
      SELECT id, title, year, rating, created_at FROM movies WHERE user_id=$1;
  `, userID)
  if err!=nil{
      fmt.Fprintf(w, "error: %v", err)
  }
  fmt.Fprintf(w, "Movies list: \n")
  for rows.Next(){
    var id int
    var title string 
    var year int
    var rating float64
    var created_at time.Time

    err := rows.Scan(&id, &title,&year,&rating,&created_at)
    if err!=nil{continue}
     fmt.Fprintf(w, "id: %d, title: %v, year: %d, rating: %.2f,  created_at: %v\n", id, title, year,rating, created_at.Format("2006-01-02 15:04:05"))
  }  
}

func main(){
  // Проверка переменной окружения
  dbURL := os.Getenv("DATABASE_URL")
  fmt.Println("DATABASE_URL =", dbURL)
  if dbURL == "" {
      log.Fatal("DATABASE_URL не найдена")
  }

  server := NewServer()
  
  createTableSQL := `
  CREATE TABLE IF NOT EXISTS movies (
  id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  year INT,
  rating DECIMAL(3,1) CHECK (rating >= 0 AND rating <= 10), -- оценка 0-10
  user_id INT REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT NOW()
  );`

  _, err := server.db.Exec(createTableSQL)
  if err != nil {
      log.Fatal("Ошибка создания таблицы:", err)
  }
  fmt.Println("Таблица tasks_list проверена/создана")

  tableUserCreate:=`
  CREATE TABLE IF NOT EXISTS users1 (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
  );`

  _, err = server.db.Exec(tableUserCreate)
  if err!= nil{
      log.Fatal("ошибка создания таблицы user:", err)
  }
  fmt.Println("таблица user  создана")

  

  http.HandleFunc("/register", server.register)
  http.HandleFunc("/login", server.login)
  http.HandleFunc("/add_movie", authMiddleware(server.new_movie))
  http.HandleFunc("/get_movie", authMiddleware(server.get_movie))
}
