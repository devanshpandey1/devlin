from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, JSON, ForeignKey, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import json
import os

Base = declarative_base()

class Project(Base):
    __tablename__ = "projects"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    targets = relationship("Target", back_populates="project", cascade="all, delete-orphan")

class Target(Base):
    __tablename__ = "targets"
    
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    ip_address = Column(String(45), nullable=False)
    hostname = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    project = relationship("Project", back_populates="targets")
    scan_results = relationship("ScanResult", back_populates="target", cascade="all, delete-orphan")

class ScanResult(Base):
    __tablename__ = "scan_results"
    
    id = Column(String(36), primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    scan_type = Column(String(50), nullable=False)
    status = Column(String(20), nullable=False)
    progress = Column(Integer, default=0)
    started_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime)
    raw_xml_path = Column(String(500))
    ai_analysis = Column(Text)
    error_message = Column(Text)
    
    target = relationship("Target", back_populates="scan_results")
    findings = relationship("Finding", back_populates="scan_result", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_result_id = Column(String(36), ForeignKey("scan_results.id"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False)
    service = Column(String(100))
    version = Column(String(255))
    state = Column(String(20), nullable=False)
    risk_level = Column(String(10))
    
    scan_result = relationship("ScanResult", back_populates="findings")

class DatabaseManager:
    def __init__(self, config: dict):
        self.config = config
        self.engine = None
        self.SessionLocal = None
        
    def initialize(self):
        """Initialize database connection with SQLCipher encryption"""
        db_config = self.config.get("database", {})
        db_path = db_config.get("path", "./data/devlin.db")
        encryption_key = db_config.get("encryption_key", "change-this-encryption-key-32-chars")
        
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        try:
            connection_string = f"sqlite+pysqlcipher://:{encryption_key}@/{db_path}"
            
            self.engine = create_engine(
                connection_string,
                echo=False,
                connect_args={"check_same_thread": False}
            )
            
            Base.metadata.create_all(bind=self.engine)
            
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
            
        except Exception as e:
            print(f"SQLCipher not available, falling back to standard SQLite: {e}")
            connection_string = f"sqlite:///{db_path}"
            
            self.engine = create_engine(
                connection_string,
                echo=False,
                connect_args={"check_same_thread": False}
            )
            
            Base.metadata.create_all(bind=self.engine)
            
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
    def get_session(self):
        """Get database session"""
        return self.SessionLocal()
