"""
Seed Default Users Script
Run this to create default user accounts in the database
"""

import os
import sys
import hashlib
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add parent directory to path to import from main.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from main.py
try:
    from main import User, RoleEnum, Base, DATABASE_URL
except ImportError:
    print("Error: Could not import from main.py")
    print("Make sure this script is in the same directory as main.py")
    sys.exit(1)

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def seed_users():
    """Create default users in the database"""
    
    # Create engine and session
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)
    
    # Create session
    db = SessionLocal()
    
    try:
        print("=" * 60)
        print("Seeding Default Users")
        print("=" * 60)
        print()
        
        default_users = [
            {
                "username": "mgr1",
                "password": "1234",
                "role": RoleEnum.management,
                "description": "Management/Admin user (full access)"
            },
            {
                "username": "proc1",
                "password": "1234",
                "role": RoleEnum.procurement,
                "description": "Procurement department user"
            },
            {
                "username": "manuf1",
                "password": "1234",
                "role": RoleEnum.manufacturing,
                "description": "Manufacturing department user"
            },
            {
                "username": "qa1",
                "password": "1234",
                "role": RoleEnum.qa,
                "description": "Quality Assurance user"
            },
            {
                "username": "pack1",
                "password": "1234",
                "role": RoleEnum.packaging,
                "description": "Packaging department user"
            },
            {
                "username": "inv1",
                "password": "1234",
                "role": RoleEnum.inventory,
                "description": "Inventory management user"
            },
        ]
        
        created_count = 0
        existing_count = 0
        
        for user_data in default_users:
            # Check if user already exists
            existing_user = db.query(User).filter(
                User.username == user_data["username"]
            ).first()
            
            if existing_user:
                print(f"⏭️  User '{user_data['username']}' already exists - skipping")
                existing_count += 1
            else:
                # Create new user
                new_user = User(
                    username=user_data["username"],
                    password=hash_password(user_data["password"]),
                    role=user_data["role"]
                )
                db.add(new_user)
                print(f"✅ Created user: {user_data['username']} ({user_data['description']})")
                created_count += 1
        
        # Commit all changes
        db.commit()
        
        print()
        print("=" * 60)
        print(f"✅ Created {created_count} new user(s)")
        print(f"⏭️  Skipped {existing_count} existing user(s)")
        print("=" * 60)
        print()
        
        # Display credentials
        if created_count > 0:
            print("Default Credentials:")
            print("-" * 60)
            for user_data in default_users:
                print(f"  {user_data['username']:15} / {user_data['password']:15} ({user_data['role'].value})")
            print("-" * 60)
            print()
        
        print("✨ You can now login at: http://localhost:8000/login")
        print()
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        db.rollback()
        return False
    finally:
        db.close()
    
    return True

if __name__ == "__main__":
    print()
    success = seed_users()
    
    if not success:
        print("❌ Failed to seed users")
        sys.exit(1)
    
    print("✅ User seeding completed successfully!")