import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_connection():
    db_url = os.getenv("DATABASE_URL")
    print(f"🔄 Testing connection to: {db_url}")
    
    try:
        # Create engine with echo=True to see SQL queries
        engine = create_engine(db_url, echo=True)
        
        # Test connection
        with engine.connect() as conn:
            print("✅ Successfully connected to the database!")
            
            # Get PostgreSQL version
            result = conn.execute(text("SELECT version();"))
            print(f"📊 PostgreSQL version: {result.scalar()}")
            
            # Check if database exists
            result = conn.execute(text("SELECT 1"))
            print(f"✅ Database connection is working!")
            
    except Exception as e:
        print(f"\n❌ Connection failed: {e}")
        print("\nTroubleshooting steps:")
        print("1. Make sure PostgreSQL is running")
        print("2. Verify the database 'threatdetection' exists")
        print("3. Check your PostgreSQL credentials in .env")
        print("4. Try connecting with pgAdmin to verify credentials")

if __name__ == "__main__":
    test_connection()
