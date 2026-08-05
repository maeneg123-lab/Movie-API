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


type Server struct{
    db *sql.DB
}

func NewServer() *Server {
    // Если её нет — используем локальную для разработки
     connStr := os.Getenv("DATABASE_URL")
    if connStr == "" {
        connStr = "user=postgres password=36863686 dbname=work_db sslmode=disable"
    }

    db, err := sql.Open("postgres", connStr)
    if err != nil {
        log.Fatal(err)
    }
    return &Server{db: db}
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

func (s *Server) saveProject(name string, description string, user_id int) error{
    _,err:=s.db.Exec(`INSERT INTO projects1 (name, description, user_id) VALUES ($1,$2,$3)`, name, description, user_id)
    return err
}

func (s *Server) saveTasks(title string, description string, status string, project_id int64, assignee_id int64, user_id int) error{
    _,err:=s.db.Exec(`INSERT INTO tasks1 (title, description, status, project_id, assignee_id, user_id) VALUES ($1,$2,$3, $4,$5,$6)`, title, description,status, project_id, assignee_id, user_id)
    return err
}


func (s *Server) register(w http.ResponseWriter, r *http.Request) {
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
    _, err = s.db.Exec("INSERT INTO users3 (username, password) VALUES ($1, $2)", username, hashedPassword)
    if err != nil {
        http.Error(w, "Username already exists", http.StatusConflict)
        return
    }

    fmt.Fprintf(w, "User registered successfully")
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
    username := r.URL.Query().Get("username")
    password := r.URL.Query().Get("password")

    if username == "" || password == "" {
        http.Error(w, "Username and password are required", http.StatusBadRequest)
        return
    }

    // Ищем пользователя в БД
    var userID int
    var hashedPassword string
    err := s.db.QueryRow("SELECT id, password FROM users3 WHERE username=$1", username).Scan(&userID, &hashedPassword)
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

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
    userID, ok := r.Context().Value("user_id").(int)
    if !ok {
        http.Error(w, "User not authorized", http.StatusUnauthorized)
        return
    }

    value := r.URL.Query()

    name := value.Get("name")
    description:= value.Get("description")

    err:= s.saveProject(name, description, userID)
    if err!=nil{
        fmt.Fprintf(w , "error: %v",  err)
        return
    }
    fmt.Fprintf(w, "success! project added")
}

func (s *Server) getProjects(w http.ResponseWriter, r *http.Request) {
    userID, ok := r.Context().Value("user_id").(int)
    if !ok {
        http.Error(w, "User not authorized", http.StatusUnauthorized)
        return
    }
    rows, err:= s.db.Query("SELECT id, name, description, created_at FROM projects1 WHERE user_id = $1", userID)
    if err!=nil{
        fmt.Fprintf(w, "error: %v", err)
        return
    }
    fmt.Fprintf(w, "projects list:\n")
    for rows.Next(){
        var id int
        var name string
        var description string
        var created_at time.Time

        err:=rows.Scan(&id,&name,&description,&created_at)
        if err!=nil{continue}
        fmt.Fprintf(w, "id: %d, name: %v, description: %v, created_at: %v", id,name,description,created_at.Format("2006-01-02 15:04:05"))
    }
}

func (s *Server) createTask(w http.ResponseWriter, r *http.Request) {
    userID, ok := r.Context().Value("user_id").(int)
    if !ok {
        http.Error(w, "User not authorized", http.StatusUnauthorized)
        return
    }

    value := r.URL.Query()

    name := value.Get("name")
    description:= value.Get("description")
    status := value.Get("status")
    project_idstr := value.Get("project_id")
    assignee_idstr:= value.Get("assignee_id")

    project_id, err := strconv.ParseInt(project_idstr, 10, 64)
    if err!= nil{
        fmt.Fprintf(w, "error! project_id not int!")
        return
    }

    assignee_id, err := strconv.ParseInt(assignee_idstr, 10, 64)
    if err!= nil{
        fmt.Fprintf(w, "error! assignee_id not int!")
        return
    }

    err = s.saveTasks(name, description, status, project_id, assignee_id, userID)
    if err!=nil{
        fmt.Fprintf(w , "error: %v",  err)
        return
    }
    fmt.Fprintf(w, "success! task added")
}

func (s *Server) getTasks(w http.ResponseWriter, r *http.Request) {
    userID, ok := r.Context().Value("user_id").(int)
    if !ok {
        http.Error(w, "User not authorized", http.StatusUnauthorized)
        return
    }

    rows, err := s.db.Query("SELECT id, title, description, status, project_id, assignee_id, created_at FROM tasks1 WHERE user_id = $1", userID)
    if err!=nil{
        fmt.Fprintf(w, "error: %v", err)
        return
    }
    fmt.Fprintf(w, "tasks list:\n")
    for rows.Next(){
        var id int
        var title string
        var description string
        var status string
        var project_id int
        var assignee_id int
        var created_at time.Time

        err:=rows.Scan(&id,&title,&description, &status, &project_id, &assignee_id, &created_at)
        if err!=nil{continue}
        fmt.Fprintf(w, "id: %d, title: %v, description: %v, status: %v, project_id: %d, assignee_id: %d,  created_at: %v", id,title,description, status, project_id, assignee_id,created_at.Format("2006-01-02 15:04:05"))
    }
}

func (s *Server) getTask(w http.ResponseWriter, r *http.Request) {
    userID, ok := r.Context().Value("user_id").(int)
    if !ok {
        http.Error(w, "User not authorized", http.StatusUnauthorized)
        return
    }

    task_idstr := r.URL.Query().Get("id")
    task_id, err:= strconv.ParseInt(task_idstr, 10, 64)
    if err!= nil{
        fmt.Fprintf(w,"error! id not int")
    }

    rows,err:= s.db.Query(`SELECT id, title, description, status, project_id, assignee_id, created_at FROM tasks1 WHERE user_id = $1 AND id=$2`, userID, task_id)
    if err!=nil{
        fmt.Fprintf(w, "error: %v", err)
        return
    }
    fmt.Fprintf(w, "projects list:\n")
    for rows.Next(){
        var id int
        var title string
        var description string
        var status string
        var project_id int
        var assignee_id int
        var created_at time.Time

        err:=rows.Scan(&id,&title,&description,&status, &project_id, &assignee_id, &created_at)
        if err!=nil{continue}
        fmt.Fprintf(w, "id: %d, title: %v, description: %v, status: %v, project_id: %d, assignee_id: %d,  created_at: %v", id,title,description, status, project_id, assignee_id,created_at.Format("2006-01-02 15:04:05"))
    }
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
    userID, ok := r.Context().Value("user_id").(int)
    if !ok {
        http.Error(w, "User not authorized", http.StatusUnauthorized)
        return
    }

    task_idstr := r.URL.Query().Get("id")
    task_id, err:= strconv.ParseInt(task_idstr, 10, 64)
    if err!= nil{
        fmt.Fprintf(w,"error! id not int")
        return
    }
    rows,err:= s.db.Query(`SELECT id, name, description, created_at FROM projects1 WHERE user_id = $1 AND id=$2`, userID, task_id)
    if err!=nil{
        fmt.Fprintf(w, "error: %v", err)
        return
    }
    fmt.Fprintf(w, "projects list:\n")
    for rows.Next(){
        var id int
        var name string
        var description string
        var created_at time.Time

        err:=rows.Scan(&id,&name,&description,&created_at)
        if err!=nil{continue}
        fmt.Fprintf(w, "id: %d, name: %v, description: %v, created_at: %v", id,name,description,created_at.Format("2006-01-02 15:04:05"))
    }
}

func (s *Server) del_task(w http.ResponseWriter, r *http.Request){
    userID, ok := r.Context().Value("user_id").(int)
    if !ok {
        http.Error(w, "User not authorized", http.StatusUnauthorized)
        return
    }

    task_idstr := r.URL.Query().Get("id")
    task_id, err:= strconv.ParseInt(task_idstr, 10, 64)
    if err!= nil{
        fmt.Fprintf(w,"error! id not int")
    }

    _, err = s.db.Query(`DELETE FROM tasks1 WHERE id=$1 AND user_id=$2`, task_id, userID)
    if err!= nil{
        fmt.Fprintf(w , "error: %v", err)
        return
    }

    fmt.Fprintf(w, "success! task: %d deleted", task_id)
}

func (s *Server) delProject(w http.ResponseWriter, r *http.Request){
    userID, ok := r.Context().Value("user_id").(int)
    if !ok {
        http.Error(w, "User not authorized", http.StatusUnauthorized)
        return
    }

    task_idstr := r.URL.Query().Get("id")
    task_id, err:= strconv.ParseInt(task_idstr, 10, 64)
    if err!= nil{
        fmt.Fprintf(w,"error! id not int")
    }

    _, err = s.db.Query(`DELETE FROM projects1 WHERE id=$1 AND user_id=$2`, task_id, userID)
    if err!= nil{
        fmt.Fprintf(w , "error: %v", err)
        return
    }

    fmt.Fprintf(w, "success! project: %d deleted", task_id)
}

func (s *Server) putProject(w http.ResponseWriter, r *http.Request){
    userID, ok := r.Context().Value("user_id").(int)
    if !ok {
        http.Error(w, "User not authorized", http.StatusUnauthorized)
        return
    }

    task_idstr := r.URL.Query().Get("id")
    id, err:= strconv.ParseInt(task_idstr, 10, 64)
    if err!= nil{
        fmt.Fprintf(w,"error! id not int")
    }

    var updates map[string]interface{}
    err = json.NewDecoder(r.Body).Decode(&updates)
    if err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }

    // Собираем динамический запрос
    query := "UPDATE projects SET "
    args := []interface{}{}
    argCounter := 1

    if name, ok := updates["name"].(string); ok {
        query += fmt.Sprintf("name = $%d, ", argCounter)
        args = append(args, name)
        argCounter++
    }
    if description, ok := updates["description"].(string); ok {
        query += fmt.Sprintf("description = $%d, ", argCounter)
        args = append(args, description)
        argCounter++
    }

    // Убираем лишнюю запятую и пробел в конце
    query = query[:len(query)-2]

    // Добавляем условие WHERE
    query += fmt.Sprintf(" WHERE id = $%d AND user_id = $%d", argCounter, argCounter+1)
    args = append(args, id, userID)

    _, err = s.db.Exec(query, args...)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    fmt.Fprintf(w, "success! project: %d upadated", id)
}

func (s *Server) put_task(w http.ResponseWriter, r *http.Request){
    userID, ok := r.Context().Value("user_id").(int)
    if !ok {
        http.Error(w, "User not authorized", http.StatusUnauthorized)
        return
    }

    task_idstr := r.URL.Query().Get("id")
    task_id, err:= strconv.ParseInt(task_idstr, 10, 64)
    if err!= nil{
        fmt.Fprintf(w,"error! id not int")
    }

    var updates map[string]interface{}
    err = json.NewDecoder(r.Body).Decode(&updates)
    if err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }

    // Собираем динамический запрос
    query := "UPDATE tasks1 SET "
    args := []interface{}{}
    argCounter := 1

    if title, ok := updates["title"].(string); ok {
        query += fmt.Sprintf("title = $%d, ", argCounter)
        args = append(args, title)
        argCounter++
    }
    if description, ok := updates["description"].(string); ok {
        query += fmt.Sprintf("description = $%d, ", argCounter)
        args = append(args, description)
        argCounter++
    }

    if status, ok := updates["status"].(string); ok {
        query += fmt.Sprintf("status = $%d, ", argCounter)
        args = append(args, status)
        argCounter++
    }

    // Убираем лишнюю запятую и пробел в конце
    query = query[:len(query)-2]

    // Добавляем условие WHERE
    query += fmt.Sprintf(" WHERE id = $%d AND user_id = $%d", argCounter, argCounter+1)
    args = append(args, task_id, userID)

    _, err = s.db.Exec(query, args...)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    fmt.Fprintf(w, "success! project: %d upadated", task_id)
}

func (s *Server) profile(w http.ResponseWriter, r *http.Request){
    userID, ok := r.Context().Value("user_id").(int)
    if !ok {
        http.Error(w, "User not authorized", http.StatusUnauthorized)
        return
    }

    fmt.Fprintf(w, "profile:\n")
    rows2, err:=s.db.Query(`SELECT id, username, password, created_at FROM users3 WHERE id=$1`, userID)
    if err!=nil{
        fmt.Fprintf(w, "error: %v", err)
        return
    }

    for rows2.Next(){
        var id int
        var username string
        var password string
        var created_at time.Time

        err = rows2.Scan(&id, &username, &password, &created_at)
        if err!=nil{
            fmt.Fprintf(w, "error: %v", err)
            continue
        }
        fmt.Fprintf(w, "id: %d, username: %v, password: %v, created_at: %v", id, username, password, created_at.Format("2006-01-02 15:04:05"))
    }
    fmt.Fprintf(w, "projects:\n")
    rows1, err:= s.db.Query("SELECT id, name, description, created_at FROM projects1 WHERE user_id = $1", userID)
    if err!=nil{
        fmt.Fprintf(w, "error: %v", err)
        return
    }
    fmt.Fprintf(w, "projects list:\n")
    for rows1.Next(){
        var id int
        var name string
        var description string
        var created_at time.Time

        err:=rows1.Scan(&id,&name,&description,&created_at)
        if err!=nil{continue}
        fmt.Fprintf(w, "id: %d, name: %v, description: %v, created_at: %v", id,name,description,created_at.Format("2006-01-02 15:04:05"))
    }

    fmt.Fprintf(w, "tasks:\n")
    rows, err := s.db.Query("SELECT id, title, description, status, project_id, assignee_id, created_at FROM tasks1 WHERE user_id = $1", userID)
    if err!=nil{
        fmt.Fprintf(w, "error: %v", err)
        return
    }
    fmt.Fprintf(w, "tasks list:\n")
    for rows.Next(){
        var id int
        var title string
        var description string
        var status string
        var project_id int
        var assignee_id int
        var created_at time.Time

        err:=rows.Scan(&id,&title,&description, &status, &project_id, &assignee_id, &created_at)
        if err!=nil{continue}
        fmt.Fprintf(w, "id: %d, title: %v, description: %v, status: %v, project_id: %d, assignee_id: %d,  created_at: %v", id,title,description, status, project_id, assignee_id,created_at.Format("2006-01-02 15:04:05"))
    }
}

func main() {
    // Проверка переменной окружения
    dbURL := os.Getenv("DATABASE_URL")
    fmt.Println("DATABASE_URL =", dbURL)
    if dbURL == "" {
        fmt.Println("⚠️ DATABASE_URL не найдена, использую локальную БД")
    }

    server := NewServer()

    // 1. Создаём таблицу пользователей (если её нет)
    createUsersSQL := `
    CREATE TABLE IF NOT EXISTS users3 (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
    );`
    _, err := server.db.Exec(createUsersSQL)
    if err != nil {
        log.Fatal("Ошибка создания таблицы users:", err)
    }
    fmt.Println("Таблица users создана")

    // 2. Создаём таблицу фильмов (если её нет)
    createMoviesSQL := `
    CREATE TABLE IF NOT EXISTS projects1 (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        user_id INT REFERENCES users(id) ON DELETE CASCADE, -- Владелец проекта
        created_at TIMESTAMP DEFAULT NOW()
    );`
    _, err = server.db.Exec(createMoviesSQL)
    if err != nil {
        log.Fatal("Ошибка создания таблицы movies:", err)
    }
    fmt.Println("Таблица movies создана")

    createtasksSQL := `
    CREATE TABLE IF NOT EXISTS tasks1 (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT CHECK (status IN ('новая', 'в работе', 'завершена')) DEFAULT 'новая',
        project_id INT REFERENCES projects1(id) ON DELETE CASCADE,
        assignee_id INT REFERENCES users(id) ON DELETE SET NULL, -- Исполнитель (может быть не назначен)
        user_id INT REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT NOW()
    );`
    _, err = server.db.Exec(createtasksSQL)
    if err != nil {
        log.Fatal("Ошибка создания таблицы movies:", err)
    }
    fmt.Println("Таблица movies создана")

    // Регистрируем маршруты
    http.HandleFunc("/register", server.register)
    http.HandleFunc("/login", server.login)
    http.HandleFunc("/add_project", authMiddleware(server.createProject))
    http.HandleFunc("/get_projects", authMiddleware(server.getProjects))
    http.HandleFunc("/get_project", authMiddleware(server.getProject))
    http.HandleFunc("/del_project", authMiddleware(server.delProject))
    http.HandleFunc("/put_project", authMiddleware(server.putProject))
    http.HandleFunc("/add_task", authMiddleware(server.createTask))
    http.HandleFunc("/get_task", authMiddleware(server.getTask))
    http.HandleFunc("/del_task", authMiddleware(server.del_task))
    http.HandleFunc("/put_task", authMiddleware(server.put_task))
    http.HandleFunc("/get_tasks", authMiddleware(server.getTasks))
    http.HandleFunc("/profile", authMiddleware(server.profile))

    // Запускаем сервер
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    fmt.Println("Сервер запущен на порту", port)
    http.ListenAndServe(":"+port, nil)
}
