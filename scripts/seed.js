/**
 * Database Seed Script
 * Creates sample data for development and testing
 * Author: IRFAN AHMMED
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Import models
const User = require('../backend/src/models/User');
const Organization = require('../backend/src/models/Organization');
const Scan = require('../backend/src/models/Scan');
const Threat = require('../backend/src/models/Threat');

// Connect to MongoDB
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/cybersec-platform');
    console.log('✅ Connected to MongoDB');
  } catch (error) {
    console.error('❌ MongoDB connection failed:', error);
    process.exit(1);
  }
};

// Sample Organizations
const sampleOrganizations = [
  {
    name: 'TechCorp Solutions',
    contactInfo: {
      email: 'admin@techcorp.com',
      phone: '+1-555-0123',
      address: {
        street: '123 Tech Street',
        city: 'San Francisco',
        state: 'CA',
        country: 'USA',
        zipCode: '94105'
      }
    },
    industry: 'technology',
    size: '201-500',
    plan: 'professional',
    status: 'active',
    usage: {
      currentUsers: 15,
      scansThisMonth: 45,
      storageUsedGB: 2.5,
      apiRequestsThisMonth: 1200
    }
  },
  {
    name: 'SecureBank Financial',
    contactInfo: {
      email: 'security@securebank.com',
      phone: '+1-555-0456'
    },
    industry: 'finance',
    size: '1000+',
    plan: 'enterprise',
    status: 'active',
    usage: {
      currentUsers: 50,
      scansThisMonth: 120,
      storageUsedGB: 15.8,
      apiRequestsThisMonth: 5500
    }
  },
  {
    name: 'HealthCare Plus',
    contactInfo: {
      email: 'it@healthcareplus.com',
      phone: '+1-555-0789'
    },
    industry: 'healthcare',
    size: '51-200',
    plan: 'basic',
    status: 'active',
    usage: {
      currentUsers: 8,
      scansThisMonth: 20,
      storageUsedGB: 1.2,
      apiRequestsThisMonth: 450
    }
  }
];

// Sample Users
const sampleUsers = [
  {
    firstName: 'Alice',
    lastName: 'Johnson',
    email: 'alice.johnson@techcorp.com',
    password: 'SecurePass123!',
    role: 'admin',
    isEmailVerified: true,
    preferences: {
      theme: 'dark',
      notifications: {
        email: true,
        slack: true
      }
    }
  },
  {
    firstName: 'Bob',
    lastName: 'Smith',
    email: 'bob.smith@techcorp.com',
    password: 'SecurePass123!',
    role: 'analyst',
    isEmailVerified: true
  },
  {
    firstName: 'Carol',
    lastName: 'Williams',
    email: 'carol.williams@securebank.com',
    password: 'SecurePass123!',
    role: 'admin',
    isEmailVerified: true
  },
  {
    firstName: 'David',
    lastName: 'Brown',
    email: 'david.brown@securebank.com',
    password: 'SecurePass123!',
    role: 'manager',
    isEmailVerified: true
  },
  {
    firstName: 'Eva',
    lastName: 'Davis',
    email: 'eva.davis@healthcareplus.com',
    password: 'SecurePass123!',
    role: 'admin',
    isEmailVerified: true
  }
];

// Sample Scans
const sampleScans = [
  {
    name: 'Weekly Network Scan',
    description: 'Automated weekly scan of internal network infrastructure',
    type: 'nmap',
    targets: [
      {
        type: 'range',
        value: '192.168.1.0/24',
        ports: ['22', '80', '443', '3389']
      }
    ],
    parameters: {
      scanType: 'comprehensive',
      timeout: 3600,
      maxThreads: 20
    },
    status: 'completed',
    priority: 'medium',
    summary: {
      totalVulnerabilities: 8,
      criticalCount: 1,
      highCount: 2,
      mediumCount: 3,
      lowCount: 2,
      hostsScanned: 25,
      openPorts: 47
    },
    vulnerabilities: [
      {
        id: 'CVE-2023-12345',
        cve: 'CVE-2023-12345',
        title: 'Remote Code Execution in SSH Server',
        description: 'A buffer overflow vulnerability in OpenSSH allows remote code execution',
        severity: 'critical',
        cvssScore: 9.8,
        target: '192.168.1.100',
        port: '22',
        service: 'ssh',
        solution: 'Update OpenSSH to version 9.4 or later',
        exploitAvailable: true,
        patchAvailable: true
      },
      {
        id: 'CVE-2023-67890',
        cve: 'CVE-2023-67890',
        title: 'SQL Injection in Web Application',
        description: 'SQL injection vulnerability in user authentication',
        severity: 'high',
        cvssScore: 8.1,
        target: '192.168.1.50',
        port: '80',
        service: 'http',
        solution: 'Implement input validation and parameterized queries'
      }
    ],
    compliance: [
      {
        framework: 'NIST',
        control: 'SC-7',
        status: 'non-compliant',
        recommendation: 'Implement proper network segmentation'
      }
    ]
  },
  {
    name: 'Web Application Security Assessment',
    description: 'Security assessment of customer-facing web applications',
    type: 'nikto',
    targets: [
      {
        type: 'url',
        value: 'https://app.techcorp.com'
      }
    ],
    status: 'running',
    priority: 'high',
    progress: {
      percentage: 65,
      currentTarget: 'https://app.techcorp.com',
      estimatedTimeRemaining: 1200
    }
  }
];

// Sample Threats
const sampleThreats = [
  {
    title: 'APT29 Phishing Campaign',
    description: 'Sophisticated phishing campaign targeting financial institutions',
    type: 'phishing',
    category: 'cyber-attack',
    severity: 'high',
    confidenceLevel: 'likely',
    threatActor: {
      name: 'APT29',
      aliases: ['Cozy Bear', 'The Dukes'],
      type: 'nation-state',
      motivation: 'espionage',
      sophistication: 'expert',
      origin: 'Russia'
    },
    indicators: [
      {
        type: 'domain',
        value: 'secure-banking-update.com',
        confidence: 'high',
        description: 'Malicious domain used in phishing emails'
      },
      {
        type: 'email',
        value: 'security@secure-banking-update.com',
        confidence: 'medium',
        description: 'Email address used in phishing campaign'
      }
    ],
    mitreAttack: [
      {
        technique: 'T1566.001',
        tactic: 'Initial Access',
        description: 'Spearphishing Attachment'
      },
      {
        technique: 'T1204.002',
        tactic: 'Execution',
        description: 'Malicious File'
      }
    ],
    status: 'active',
    riskScore: 85
  },
  {
    title: 'Ransomware Infrastructure Discovery',
    description: 'Command and control infrastructure for LockBit ransomware',
    type: 'ransomware',
    category: 'cyber-attack',
    severity: 'critical',
    confidenceLevel: 'confirmed',
    indicators: [
      {
        type: 'ip',
        value: '185.220.100.245',
        confidence: 'high',
        description: 'C2 server for ransomware operations'
      },
      {
        type: 'hash',
        value: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6',
        confidence: 'high',
        description: 'SHA256 hash of ransomware payload'
      }
    ],
    status: 'active',
    riskScore: 95
  }
];

// Seeding functions
const seedOrganizations = async () => {
  console.log('🏢 Seeding organizations...');
  
  for (const orgData of sampleOrganizations) {
    try {
      const existing = await Organization.findOne({ name: orgData.name });
      if (!existing) {
        const org = new Organization(orgData);
        await org.save();
        console.log(`   ✅ Created organization: ${orgData.name}`);
      } else {
        console.log(`   ⚠️  Organization already exists: ${orgData.name}`);
      }
    } catch (error) {
      console.error(`   ❌ Error creating organization ${orgData.name}:`, error.message);
    }
  }
};

const seedUsers = async () => {
  console.log('👥 Seeding users...');
  
  const organizations = await Organization.find();
  
  for (let i = 0; i < sampleUsers.length; i++) {
    const userData = sampleUsers[i];
    
    try {
      const existing = await User.findOne({ email: userData.email });
      if (!existing) {
        // Assign organization based on email domain
        let org;
        if (userData.email.includes('techcorp.com')) {
          org = organizations.find(o => o.name === 'TechCorp Solutions');
        } else if (userData.email.includes('securebank.com')) {
          org = organizations.find(o => o.name === 'SecureBank Financial');
        } else if (userData.email.includes('healthcareplus.com')) {
          org = organizations.find(o => o.name === 'HealthCare Plus');
        }
        
        if (org) {
          userData.organization = org._id;
          
          // Set first user as organization owner
          if (!org.owner) {
            org.owner = userData._id;
            await org.save();
          }
        }
        
        const user = new User(userData);
        await user.save();
        console.log(`   ✅ Created user: ${userData.email}`);
      } else {
        console.log(`   ⚠️  User already exists: ${userData.email}`);
      }
    } catch (error) {
      console.error(`   ❌ Error creating user ${userData.email}:`, error.message);
    }
  }
};

const seedScans = async () => {
  console.log('🔍 Seeding scans...');
  
  const organizations = await Organization.find();
  const users = await User.find();
  
  for (const scanData of sampleScans) {
    try {
      const existing = await Scan.findOne({ name: scanData.name });
      if (!existing) {
        // Assign to TechCorp organization and first admin user
        const org = organizations.find(o => o.name === 'TechCorp Solutions');
        const user = users.find(u => u.organization?.toString() === org?._id.toString() && u.role === 'admin');
        
        if (org && user) {
          scanData.organization = org._id;
          scanData.createdBy = user._id;
          
          const scan = new Scan(scanData);
          await scan.save();
          console.log(`   ✅ Created scan: ${scanData.name}`);
        }
      } else {
        console.log(`   ⚠️  Scan already exists: ${scanData.name}`);
      }
    } catch (error) {
      console.error(`   ❌ Error creating scan ${scanData.name}:`, error.message);
    }
  }
};

const seedThreats = async () => {
  console.log('⚠️  Seeding threats...');
  
  const organizations = await Organization.find();
  const users = await User.find();
  
  for (const threatData of sampleThreats) {
    try {
      const existing = await Threat.findOne({ title: threatData.title });
      if (!existing) {
        // Assign to SecureBank organization
        const org = organizations.find(o => o.name === 'SecureBank Financial');
        const user = users.find(u => u.organization?.toString() === org?._id.toString());
        
        if (org && user) {
          threatData.organization = org._id;
          threatData.discoveredBy = user._id;
          
          const threat = new Threat(threatData);
          await threat.save();
          console.log(`   ✅ Created threat: ${threatData.title}`);
        }
      } else {
        console.log(`   ⚠️  Threat already exists: ${threatData.title}`);
      }
    } catch (error) {
      console.error(`   ❌ Error creating threat ${threatData.title}:`, error.message);
    }
  }
};

// Main seeding function
const seedDatabase = async () => {
  try {
    console.log('🌱 Starting database seeding...\n');
    
    await connectDB();
    
    // Clear existing data if specified
    if (process.argv.includes('--fresh')) {
      console.log('🗑️  Clearing existing data...');
      await Promise.all([
        User.deleteMany({}),
        Organization.deleteMany({}),
        Scan.deleteMany({}),
        Threat.deleteMany({})
      ]);
      console.log('   ✅ Existing data cleared\n');
    }
    
    // Seed data in order
    await seedOrganizations();
    await seedUsers();
    await seedScans();
    await seedThreats();
    
    console.log('\n🎉 Database seeding completed successfully!');
    console.log('\n📝 Sample login credentials:');
    console.log('   Email: alice.johnson@techcorp.com');
    console.log('   Password: SecurePass123!');
    console.log('   Role: Admin\n');
    
    process.exit(0);
  } catch (error) {
    console.error('\n❌ Database seeding failed:', error);
    process.exit(1);
  }
};

// Run if called directly
if (require.main === module) {
  seedDatabase();
}

module.exports = {
  seedDatabase,
  seedOrganizations,
  seedUsers,
  seedScans,
  seedThreats
};