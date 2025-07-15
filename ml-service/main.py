"""
AI-Powered Cybersecurity Platform - ML Service
Author: IRFAN AHMMED

FastAPI-based machine learning microservice for:
- Risk prediction and scoring
- Threat analysis and classification
- Vulnerability assessment
- Anomaly detection
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
import uvicorn
import logging
import numpy as np
import pandas as pd
from datetime import datetime
import joblib
import os
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Cybersecurity ML Service",
    description="AI/ML microservice for cybersecurity risk assessment and threat analysis",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure based on your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Models directory
MODELS_DIR = Path("models")
MODELS_DIR.mkdir(exist_ok=True)

# Pydantic models for request/response
class VulnerabilityData(BaseModel):
    """Vulnerability data for risk assessment"""
    cve_id: Optional[str] = None
    cvss_score: float = Field(..., ge=0, le=10)
    severity: str = Field(..., regex="^(critical|high|medium|low|info)$")
    exploit_available: bool = False
    patch_available: bool = False
    age_days: int = Field(..., ge=0)
    affected_systems: int = Field(..., ge=0)
    network_exposure: bool = False
    
class ThreatData(BaseModel):
    """Threat intelligence data for analysis"""
    threat_type: str
    confidence_level: str = Field(..., regex="^(confirmed|likely|possible|unlikely|unknown)$")
    severity: str = Field(..., regex="^(critical|high|medium|low|info)$")
    indicators_count: int = Field(..., ge=0)
    campaign_active: bool = False
    recent_activity: bool = False
    attribution: Optional[str] = None
    
class OrganizationProfile(BaseModel):
    """Organization profile for risk assessment"""
    industry: str
    size: str = Field(..., regex="^(1-10|11-50|51-200|201-500|501-1000|1000+)$")
    security_maturity: int = Field(..., ge=1, le=5)
    compliance_frameworks: List[str] = []
    critical_assets: int = Field(..., ge=0)
    internet_exposure: int = Field(..., ge=0)
    
class RiskAssessmentRequest(BaseModel):
    """Risk assessment request"""
    vulnerabilities: List[VulnerabilityData]
    threats: List[ThreatData]
    organization: OrganizationProfile
    scan_results: Dict[str, Any] = {}
    
class RiskScore(BaseModel):
    """Risk score response"""
    overall_risk: int = Field(..., ge=0, le=100)
    vulnerability_risk: int = Field(..., ge=0, le=100)
    threat_risk: int = Field(..., ge=0, le=100)
    exposure_risk: int = Field(..., ge=0, le=100)
    risk_level: str
    recommendations: List[str]
    confidence: float = Field(..., ge=0, le=1)
    
class ThreatClassification(BaseModel):
    """Threat classification response"""
    threat_family: str
    attack_vector: str
    kill_chain_phase: str
    mitre_techniques: List[str]
    confidence: float = Field(..., ge=0, le=1)
    severity_prediction: str
    
class AnomalyData(BaseModel):
    """Network/system data for anomaly detection"""
    timestamp: datetime
    source_ip: str
    destination_ip: str
    port: int
    protocol: str
    bytes_transferred: int
    packets_count: int
    connection_duration: float
    flags: List[str] = []
    
class AnomalyResult(BaseModel):
    """Anomaly detection result"""
    is_anomaly: bool
    anomaly_score: float = Field(..., ge=0, le=1)
    anomaly_type: str
    confidence: float = Field(..., ge=0, le=1)
    explanation: str

# Authentication dependency
async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify API token (simplified for demo)"""
    # In production, verify against your auth service
    if credentials.credentials != os.getenv("ML_API_KEY", "demo-key"):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return credentials.credentials

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "ml-service",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }

# Risk assessment endpoint
@app.post("/risk-assessment", response_model=RiskScore)
async def assess_risk(
    request: RiskAssessmentRequest,
    background_tasks: BackgroundTasks,
    token: str = Depends(verify_token)
):
    """
    Assess overall cybersecurity risk based on vulnerabilities, threats, and organization profile
    """
    try:
        logger.info(f"Processing risk assessment for organization with {len(request.vulnerabilities)} vulnerabilities")
        
        # Calculate vulnerability risk
        vuln_risk = calculate_vulnerability_risk(request.vulnerabilities)
        
        # Calculate threat risk
        threat_risk = calculate_threat_risk(request.threats)
        
        # Calculate exposure risk
        exposure_risk = calculate_exposure_risk(request.organization)
        
        # Calculate overall risk (weighted average)
        overall_risk = int(
            vuln_risk * 0.4 +
            threat_risk * 0.35 +
            exposure_risk * 0.25
        )
        
        # Determine risk level
        risk_level = get_risk_level(overall_risk)
        
        # Generate recommendations
        recommendations = generate_recommendations(
            request.vulnerabilities, 
            request.threats, 
            request.organization,
            overall_risk
        )
        
        # Calculate confidence score
        confidence = calculate_confidence_score(request)
        
        # Background task: Update ML models with new data
        background_tasks.add_task(update_models_async, request)
        
        return RiskScore(
            overall_risk=overall_risk,
            vulnerability_risk=vuln_risk,
            threat_risk=threat_risk,
            exposure_risk=exposure_risk,
            risk_level=risk_level,
            recommendations=recommendations,
            confidence=confidence
        )
        
    except Exception as e:
        logger.error(f"Error in risk assessment: {str(e)}")
        raise HTTPException(status_code=500, detail="Risk assessment failed")

# Threat classification endpoint
@app.post("/threat-classification", response_model=ThreatClassification)
async def classify_threat(
    threat_data: ThreatData,
    indicators: List[str],
    token: str = Depends(verify_token)
):
    """
    Classify threat based on indicators and threat intelligence
    """
    try:
        logger.info(f"Classifying threat: {threat_data.threat_type}")
        
        # Simulate threat classification using ML model
        classification = classify_threat_with_ml(threat_data, indicators)
        
        return classification
        
    except Exception as e:
        logger.error(f"Error in threat classification: {str(e)}")
        raise HTTPException(status_code=500, detail="Threat classification failed")

# Anomaly detection endpoint
@app.post("/anomaly-detection", response_model=List[AnomalyResult])
async def detect_anomalies(
    network_data: List[AnomalyData],
    token: str = Depends(verify_token)
):
    """
    Detect anomalies in network traffic or system behavior
    """
    try:
        logger.info(f"Analyzing {len(network_data)} network events for anomalies")
        
        results = []
        for data in network_data:
            anomaly_result = detect_network_anomaly(data)
            results.append(anomaly_result)
        
        return results
        
    except Exception as e:
        logger.error(f"Error in anomaly detection: {str(e)}")
        raise HTTPException(status_code=500, detail="Anomaly detection failed")

# MITRE ATT&CK mapping endpoint
@app.post("/mitre-mapping")
async def map_to_mitre(
    attack_data: Dict[str, Any],
    token: str = Depends(verify_token)
):
    """
    Map attack patterns to MITRE ATT&CK framework
    """
    try:
        logger.info("Mapping attack patterns to MITRE ATT&CK")
        
        # Simulate MITRE mapping
        mapping = map_to_mitre_attack(attack_data)
        
        return {
            "mitre_mapping": mapping,
            "confidence": 0.85,
            "techniques_identified": len(mapping),
            "tactics": list(set([t["tactic"] for t in mapping]))
        }
        
    except Exception as e:
        logger.error(f"Error in MITRE mapping: {str(e)}")
        raise HTTPException(status_code=500, detail="MITRE mapping failed")

# Model training endpoint
@app.post("/train-model")
async def train_model(
    model_type: str,
    training_data: Dict[str, Any],
    background_tasks: BackgroundTasks,
    token: str = Depends(verify_token)
):
    """
    Train or retrain ML models with new data
    """
    try:
        logger.info(f"Initiating training for {model_type} model")
        
        # Background task for model training
        background_tasks.add_task(train_model_async, model_type, training_data)
        
        return {
            "status": "training_initiated",
            "model_type": model_type,
            "estimated_duration": "15-30 minutes",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error initiating model training: {str(e)}")
        raise HTTPException(status_code=500, detail="Model training failed")

# Helper functions

def calculate_vulnerability_risk(vulnerabilities: List[VulnerabilityData]) -> int:
    """Calculate risk score based on vulnerabilities"""
    if not vulnerabilities:
        return 0
    
    total_score = 0
    for vuln in vulnerabilities:
        # Base score from CVSS
        score = vuln.cvss_score * 10  # Convert to 0-100 scale
        
        # Modifiers
        if vuln.exploit_available:
            score *= 1.3
        if not vuln.patch_available:
            score *= 1.2
        if vuln.network_exposure:
            score *= 1.4
        if vuln.age_days > 30:
            score *= 1.1
        
        total_score += min(score, 100)
    
    return min(int(total_score / len(vulnerabilities)), 100)

def calculate_threat_risk(threats: List[ThreatData]) -> int:
    """Calculate risk score based on threat intelligence"""
    if not threats:
        return 0
    
    severity_weights = {"critical": 90, "high": 70, "medium": 50, "low": 30, "info": 10}
    confidence_weights = {"confirmed": 1.0, "likely": 0.8, "possible": 0.6, "unlikely": 0.4, "unknown": 0.2}
    
    total_score = 0
    for threat in threats:
        base_score = severity_weights.get(threat.severity, 10)
        confidence_multiplier = confidence_weights.get(threat.confidence_level, 0.2)
        
        score = base_score * confidence_multiplier
        
        if threat.campaign_active:
            score *= 1.3
        if threat.recent_activity:
            score *= 1.2
        
        total_score += score
    
    return min(int(total_score / len(threats)), 100)

def calculate_exposure_risk(org: OrganizationProfile) -> int:
    """Calculate risk score based on organization exposure"""
    industry_risk = {
        "finance": 85, "healthcare": 80, "government": 90, "technology": 75,
        "energy": 85, "education": 60, "retail": 70, "manufacturing": 65
    }
    
    size_risk = {
        "1-10": 40, "11-50": 50, "51-200": 60, 
        "201-500": 70, "501-1000": 75, "1000+": 80
    }
    
    base_risk = industry_risk.get(org.industry, 50)
    size_multiplier = size_risk.get(org.size, 50) / 50
    
    # Security maturity reduces risk
    maturity_reduction = (org.security_maturity - 1) * 0.15
    
    # Exposure factors
    exposure_factor = min(org.internet_exposure / 100, 1.0) * 0.2
    
    risk = base_risk * size_multiplier * (1 - maturity_reduction) + (exposure_factor * 100)
    
    return min(int(risk), 100)

def get_risk_level(score: int) -> str:
    """Convert risk score to risk level"""
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    elif score >= 20:
        return "low"
    else:
        return "minimal"

def generate_recommendations(vulnerabilities, threats, org, overall_risk) -> List[str]:
    """Generate security recommendations based on assessment"""
    recommendations = []
    
    if overall_risk >= 80:
        recommendations.append("Implement immediate incident response procedures")
        recommendations.append("Consider engaging external security experts")
    
    if vulnerabilities:
        critical_vulns = [v for v in vulnerabilities if v.severity == "critical"]
        if critical_vulns:
            recommendations.append(f"Prioritize patching {len(critical_vulns)} critical vulnerabilities")
    
    if threats:
        active_threats = [t for t in threats if t.recent_activity]
        if active_threats:
            recommendations.append("Enhance monitoring for active threat campaigns")
    
    if org.security_maturity < 3:
        recommendations.append("Invest in security awareness training")
        recommendations.append("Implement security policies and procedures")
    
    if not recommendations:
        recommendations.append("Maintain current security posture")
        recommendations.append("Continue regular security assessments")
    
    return recommendations

def calculate_confidence_score(request: RiskAssessmentRequest) -> float:
    """Calculate confidence in the risk assessment"""
    factors = []
    
    # Data completeness
    if request.vulnerabilities:
        factors.append(0.9)
    if request.threats:
        factors.append(0.85)
    if request.scan_results:
        factors.append(0.8)
    
    # Organization profile completeness
    if request.organization.compliance_frameworks:
        factors.append(0.75)
    
    return min(sum(factors) / len(factors) if factors else 0.5, 1.0)

def classify_threat_with_ml(threat_data: ThreatData, indicators: List[str]) -> ThreatClassification:
    """Classify threat using ML model (simplified simulation)"""
    # This would use trained ML models in production
    threat_families = {
        "malware": ["trojan", "ransomware", "backdoor"],
        "phishing": ["credential_harvesting", "business_email_compromise"],
        "apt": ["lateral_movement", "persistence", "exfiltration"]
    }
    
    # Simulate classification
    family = "malware"  # Would be predicted by ML model
    
    return ThreatClassification(
        threat_family=family,
        attack_vector="email",
        kill_chain_phase="delivery",
        mitre_techniques=["T1566.001", "T1204.002"],
        confidence=0.87,
        severity_prediction=threat_data.severity
    )

def detect_network_anomaly(data: AnomalyData) -> AnomalyResult:
    """Detect anomalies in network data (simplified simulation)"""
    # This would use trained anomaly detection models
    
    # Simple rule-based detection for demo
    is_anomaly = False
    anomaly_score = 0.0
    anomaly_type = "normal"
    explanation = "Normal network behavior"
    
    # Check for large data transfers
    if data.bytes_transferred > 1000000:  # 1MB threshold
        is_anomaly = True
        anomaly_score = 0.8
        anomaly_type = "data_exfiltration"
        explanation = "Large data transfer detected"
    
    # Check for unusual ports
    suspicious_ports = [4444, 6666, 31337]
    if data.port in suspicious_ports:
        is_anomaly = True
        anomaly_score = 0.9
        anomaly_type = "suspicious_port"
        explanation = f"Connection to suspicious port {data.port}"
    
    return AnomalyResult(
        is_anomaly=is_anomaly,
        anomaly_score=anomaly_score,
        anomaly_type=anomaly_type,
        confidence=0.85,
        explanation=explanation
    )

def map_to_mitre_attack(attack_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """Map attack patterns to MITRE ATT&CK (simplified simulation)"""
    # This would use trained models and MITRE ATT&CK knowledge base
    
    sample_mapping = [
        {
            "technique": "T1566.001",
            "technique_name": "Spearphishing Attachment",
            "tactic": "Initial Access",
            "description": "Email with malicious attachment"
        },
        {
            "technique": "T1204.002",
            "technique_name": "Malicious File",
            "tactic": "Execution",
            "description": "User executed malicious file"
        }
    ]
    
    return sample_mapping

async def update_models_async(request: RiskAssessmentRequest):
    """Update ML models with new assessment data (background task)"""
    logger.info("Updating ML models with new assessment data")
    # Implement model update logic
    pass

async def train_model_async(model_type: str, training_data: Dict[str, Any]):
    """Train ML model asynchronously"""
    logger.info(f"Training {model_type} model with new data")
    # Implement model training logic
    pass

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )