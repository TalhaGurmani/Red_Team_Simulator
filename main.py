from app import app, init_db

def main():
    
    init_db()
   
    app.run(host="0.0.0.0", port=5000, debug=True)

if __name__ == "__main__":
    main()