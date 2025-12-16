import psycopg2
from psycopg2 import sql
import sys

def test_connection():
    print("🔍 Testing PostgreSQL connection...")
    print(f"📌 Connection details: postgresql://postgres:****@localhost:5432/threatdetection")
    
    try:
        # Test basic connection
        print("\n🔌 Attempting to connect to PostgreSQL...")
        conn = psycopg2.connect(
            dbname="threatdetection",
            user="postgres",
            password="gowtham098",
            host="localhost",
            port="5432"
        )
        print("✅ Successfully connected to PostgreSQL!")

        # Get database version
        with conn.cursor() as cur:
            cur.execute("SELECT version();")
            db_version = cur.fetchone()
            print(f"\n📊 PostgreSQL Version: {db_version[0]}")

            # Check if database exists
            cur.execute("SELECT 1 FROM pg_database WHERE datname = 'threatdetection'")
            exists = cur.fetchone()
            if exists:
                print("✅ Database 'threatdetection' exists")
            else:
                print("❌ Database 'threatdetection' does not exist")
                print("   Run: CREATE DATABASE threatdetection;")

            # List all databases
            print("\n📋 Available databases:")
            cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
            for db in cur.fetchall():
                print(f"   - {db[0]}")

        conn.close()
        return True

    except psycopg2.OperationalError as e:
        print(f"\n❌ Connection failed: {e}")
        print("\n🔧 Troubleshooting steps:")
        print("1. Make sure PostgreSQL is running")
        print("2. Check if the database 'threatdetection' exists")
        print("3. Verify the credentials in .env match your PostgreSQL setup")
        print("4. Try connecting with: psql -U postgres -h localhost -p 5432 -d threatdetection")
        return False
    except Exception as e:
        print(f"\n❌ An unexpected error occurred: {e}")
        return False

if __name__ == "__main__":
    test_connection()