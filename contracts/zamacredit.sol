// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import "fhevm/lib/TFHE.sol";
import "fhevm/config/ZamaFHEVMConfig.sol";

/**
 * @title RiskScore
 * @notice Privacy-preserving health risk score calculation using FHE
 * @dev Uses Zama's FHEVM for encrypted health data computation
 */
contract RiskScore is SepoliaZamaFHEVMConfig {
    
    // Encrypted health data structure
    struct HealthData {
        euint32 height;          // Height in cm (100-250)
        euint32 weight;          // Weight in kg (30-300)
        euint32 systolic;        // Systolic BP (70-250)
        euint32 diastolic;       // Diastolic BP (40-150)
        euint32 hdlCholesterol;  // HDL in mg/dL (20-100)
        euint32 ldlCholesterol;  // LDL in mg/dL (50-300)
        euint32 triglycerides;   // Triglycerides in mg/dL (50-500)
        euint32 totalCholesterol; // Total cholesterol in mg/dL (100-400)
        euint32 bloodSugar;      // HbA1c * 10 or fasting glucose (40-200)
        euint32 pulseRate;       // Pulse rate (40-150)
        euint32 age;             // Age in years (18-100)
        euint8 gender;           // 0 = female, 1 = male
        euint32 riskScore;       // Calculated risk score
        bool dataSubmitted;      // Track if data is submitted
        bool scoreComputed;      // Track if score is computed
    }
    
    // Insurance company data
    struct InsuranceCompany {
        address companyAddress;
        string companyName;
        bool isRegistered;
    }
    
    // Mappings
    mapping(address => mapping(address => HealthData)) public userHealthData; // user => company => data
    mapping(address => InsuranceCompany) public insuranceCompanies;
    mapping(address => mapping(address => bool)) public userPermissions; // user => company => permission
    
    // Events
    event HealthDataSubmitted(
        address indexed user,
        address indexed insuranceCompany,
        uint256 timestamp
    );
    
    event RiskScoreComputed(
        address indexed user,
        address indexed insuranceCompany,
        uint256 timestamp
    );
    
    event RiskScoreSent(
        address indexed user,
        address indexed insuranceCompany,
        uint256 timestamp
    );
    
    event InsuranceCompanyRegistered(
        address indexed companyAddress,
        string companyName
    );
    
    // Modifiers
    modifier onlyRegisteredCompany() {
        require(insuranceCompanies[msg.sender].isRegistered, "Company not registered");
        _;
    }
    
    modifier validHealthData(
        uint32 height,
        uint32 weight,
        uint32 systolic,
        uint32 diastolic,
        uint32 hdl,
        uint32 ldl,
        uint32 triglycerides,
        uint32 totalChol,
        uint32 bloodSugar,
        uint32 pulse,
        uint32 age,
        uint8 gender
    ) {
        // Validate health data ranges
        require(height >= 100 && height <= 250, "Invalid height range");
        require(weight >= 30 && weight <= 300, "Invalid weight range");
        require(systolic >= 70 && systolic <= 250, "Invalid systolic BP range");
        require(diastolic >= 40 && diastolic <= 150, "Invalid diastolic BP range");
        require(hdl >= 20 && hdl <= 100, "Invalid HDL range");
        require(ldl >= 50 && ldl <= 300, "Invalid LDL range");
        require(triglycerides >= 50 && triglycerides <= 500, "Invalid triglycerides range");
        require(totalChol >= 100 && totalChol <= 400, "Invalid total cholesterol range");
        require(bloodSugar >= 40 && bloodSugar <= 200, "Invalid blood sugar range");
        require(pulse >= 40 && pulse <= 150, "Invalid pulse rate range");
        require(age >= 18 && age <= 100, "Invalid age range");
        require(gender <= 1, "Invalid gender value");
        _;
    }
    
    // Register insurance company
    function registerInsuranceCompany(string memory companyName) external {
        require(!insuranceCompanies[msg.sender].isRegistered, "Company already registered");
        require(bytes(companyName).length > 0, "Company name required");
        
        insuranceCompanies[msg.sender] = InsuranceCompany({
            companyAddress: msg.sender,
            companyName: companyName,
            isRegistered: true
        });
        
        emit InsuranceCompanyRegistered(msg.sender, companyName);
    }
    
    /**
     * @notice Submit encrypted health data for risk assessment
     * @param insuranceCompany Address of the insurance company requesting the data
     * @param encryptedHeight Encrypted height value
     * @param encryptedWeight Encrypted weight value
     * @param encryptedSystolic Encrypted systolic BP
     * @param encryptedDiastolic Encrypted diastolic BP
     * @param encryptedHDL Encrypted HDL cholesterol
     * @param encryptedLDL Encrypted LDL cholesterol
     * @param encryptedTriglycerides Encrypted triglycerides
     * @param encryptedTotalChol Encrypted total cholesterol
     * @param encryptedBloodSugar Encrypted blood sugar/HbA1c
     * @param encryptedPulse Encrypted pulse rate
     * @param encryptedAge Encrypted age
     * @param encryptedGender Encrypted gender
     * @param inputProof ZK proof for encrypted inputs
     */
    function submitHealthData(
        address insuranceCompany,
        einput encryptedHeight,
        einput encryptedWeight,
        einput encryptedSystolic,
        einput encryptedDiastolic,
        einput encryptedHDL,
        einput encryptedLDL,
        einput encryptedTriglycerides,
        einput encryptedTotalChol,
        einput encryptedBloodSugar,
        einput encryptedPulse,
        einput encryptedAge,
        einput encryptedGender,
        bytes calldata inputProof
    ) external {
        require(insuranceCompanies[insuranceCompany].isRegistered, "Insurance company not registered");
        require(!userHealthData[msg.sender][insuranceCompany].dataSubmitted, "Data already submitted");
        
        // Convert encrypted inputs to euint types with verification
        euint32 height = TFHE.asEuint32(encryptedHeight, inputProof);
        euint32 weight = TFHE.asEuint32(encryptedWeight, inputProof);
        euint32 systolic = TFHE.asEuint32(encryptedSystolic, inputProof);
        euint32 diastolic = TFHE.asEuint32(encryptedDiastolic, inputProof);
        euint32 hdl = TFHE.asEuint32(encryptedHDL, inputProof);
        euint32 ldl = TFHE.asEuint32(encryptedLDL, inputProof);
        euint32 triglycerides = TFHE.asEuint32(encryptedTriglycerides, inputProof);
        euint32 totalChol = TFHE.asEuint32(encryptedTotalChol, inputProof);
        euint32 bloodSugar = TFHE.asEuint32(encryptedBloodSugar, inputProof);
        euint32 pulse = TFHE.asEuint32(encryptedPulse, inputProof);
        euint32 age = TFHE.asEuint32(encryptedAge, inputProof);
        euint8 gender = TFHE.asEuint8(encryptedGender, inputProof);
        
        // Store encrypted health data
        userHealthData[msg.sender][insuranceCompany] = HealthData({
            height: height,
            weight: weight,
            systolic: systolic,
            diastolic: diastolic,
            hdlCholesterol: hdl,
            ldlCholesterol: ldl,
            triglycerides: triglycerides,
            totalCholesterol: totalChol,
            bloodSugar: bloodSugar,
            pulseRate: pulse,
            age: age,
            gender: gender,
            riskScore: TFHE.asEuint32(0),
            dataSubmitted: true,
            scoreComputed: false
        });
        
        // Grant permissions for the contract to operate on the data
        TFHE.allowThis(height);
        TFHE.allowThis(weight);
        TFHE.allowThis(systolic);
        TFHE.allowThis(diastolic);
        TFHE.allowThis(hdl);
        TFHE.allowThis(ldl);
        TFHE.allowThis(triglycerides);
        TFHE.allowThis(totalChol);
        TFHE.allowThis(bloodSugar);
        TFHE.allowThis(pulse);
        TFHE.allowThis(age);
        TFHE.allowThis(gender);
        
        emit HealthDataSubmitted(msg.sender, insuranceCompany, block.timestamp);
    }
    
    /**
     * @notice Compute risk score on encrypted health data
     * @param user Address of the user whose data to compute
     * @param insuranceCompany Address of the insurance company
     */ 
    function computeRiskScore(address user, address insuranceCompany) external {
        require(insuranceCompanies[insuranceCompany].isRegistered, "Insurance company not registered");
        require(userHealthData[user][insuranceCompany].dataSubmitted, "No health data submitted");
        require(!userHealthData[user][insuranceCompany].scoreComputed, "Score already computed");
        
        HealthData storage data = userHealthData[user][insuranceCompany];
        
        // Calculate BMI: (weight * 10000) / (height * height)
        euint32 heightSquared = TFHE.mul(data.height, data.height);
        euint32 weightTimes10000 = TFHE.mul(data.weight, TFHE.asEuint32(10000));
        euint32 bmi = TFHE.div(weightTimes10000, heightSquared);
        
        // Initialize risk score
        euint32 riskScore = TFHE.asEuint32(0);
        
        // Age factor (strongest factor): age * 2
        euint32 ageScore = TFHE.mul(data.age, TFHE.asEuint32(2));
        riskScore = TFHE.add(riskScore, ageScore);
        
        // Gender factor: male = +10, female = +0
        euint32 genderScore = TFHE.mul(data.gender, TFHE.asEuint32(10));
        riskScore = TFHE.add(riskScore, genderScore);
        
        // BMI factor: BMI > 30 = +20, BMI > 25 = +10
        ebool bmiHigh = TFHE.gt(bmi, TFHE.asEuint32(30));
        ebool bmiModerate = TFHE.gt(bmi, TFHE.asEuint32(25));
        euint32 bmiScore = TFHE.select(bmiHigh, TFHE.asEuint32(20), 
                           TFHE.select(bmiModerate, TFHE.asEuint32(10), TFHE.asEuint32(0)));
        riskScore = TFHE.add(riskScore, bmiScore);
        
        // Blood pressure factor: systolic > 140 or diastolic > 90 = +15
        ebool highSystolic = TFHE.gt(data.systolic, TFHE.asEuint32(140));
        ebool highDiastolic = TFHE.gt(data.diastolic, TFHE.asEuint32(90));
        ebool highBP = TFHE.or(highSystolic, highDiastolic);
        euint32 bpScore = TFHE.select(highBP, TFHE.asEuint32(15), TFHE.asEuint32(0));
        riskScore = TFHE.add(riskScore, bpScore);
        
        // Cholesterol factor: LDL > 160 = +10, HDL < 40 = +10
        ebool highLDL = TFHE.gt(data.ldlCholesterol, TFHE.asEuint32(160));
        ebool lowHDL = TFHE.lt(data.hdlCholesterol, TFHE.asEuint32(40));
        euint32 cholScore = TFHE.add(
            TFHE.select(highLDL, TFHE.asEuint32(10), TFHE.asEuint32(0)),
            TFHE.select(lowHDL, TFHE.asEuint32(10), TFHE.asEuint32(0))
        );
        riskScore = TFHE.add(riskScore, cholScore);
        
        // Blood sugar factor: > 126 (diabetes) = +25, > 100 (prediabetes) = +10
        ebool diabetes = TFHE.gt(data.bloodSugar, TFHE.asEuint32(126));
        ebool prediabetes = TFHE.gt(data.bloodSugar, TFHE.asEuint32(100));
        euint32 sugarScore = TFHE.select(diabetes, TFHE.asEuint32(25),
                            TFHE.select(prediabetes, TFHE.asEuint32(10), TFHE.asEuint32(0)));
        riskScore = TFHE.add(riskScore, sugarScore);
        
        // Pulse rate factor: > 100 = +5
        ebool highPulse = TFHE.gt(data.pulseRate, TFHE.asEuint32(100));
        euint32 pulseScore = TFHE.select(highPulse, TFHE.asEuint32(5), TFHE.asEuint32(0));
        riskScore = TFHE.add(riskScore, pulseScore);
        
        // Store the computed risk score
        data.riskScore = riskScore;
        data.scoreComputed = true;
        
        // Allow contract to access the risk score
        TFHE.allowThis(riskScore);
        
        emit RiskScoreComputed(user, insuranceCompany, block.timestamp);
    }
    
    /**
     * @notice Grant permission to insurance company to access risk score
     * @param insuranceCompany Address of the insurance company
     */
    function grantRiskScorePermission(address insuranceCompany) external {
        require(insuranceCompanies[insuranceCompany].isRegistered, "Insurance company not registered");
        require(userHealthData[msg.sender][insuranceCompany].scoreComputed, "Risk score not computed");
        
        // Grant permission to insurance company to decrypt the risk score
        TFHE.allow(userHealthData[msg.sender][insuranceCompany].riskScore, insuranceCompany);
        
        // Record permission granted
        userPermissions[msg.sender][insuranceCompany] = true;
        
        emit RiskScoreSent(msg.sender, insuranceCompany, block.timestamp);
    }
    
    /**
     * @notice Get encrypted risk score (only accessible by authorized parties)
     * @param user Address of the user
     * @param insuranceCompany Address of the insurance company
     */
    function getRiskScore(address user, address insuranceCompany) external view returns (euint32) {
        require(userHealthData[user][insuranceCompany].scoreComputed, "Risk score not computed");
        require(
            msg.sender == user || 
            (msg.sender == insuranceCompany && userPermissions[user][insuranceCompany]),
            "Not authorized to access risk score"
        );
        
        return userHealthData[user][insuranceCompany].riskScore;
    }
    
    /**
     * @notice Check if health data has been submitted
     */
    function isHealthDataSubmitted(address user, address insuranceCompany) external view returns (bool) {
        return userHealthData[user][insuranceCompany].dataSubmitted;
    }
    
    /**
     * @notice Check if risk score has been computed
     */
    function isRiskScoreComputed(address user, address insuranceCompany) external view returns (bool) {
        return userHealthData[user][insuranceCompany].scoreComputed;
    }
    
    /**
     * @notice Check if permission has been granted to insurance company
     */
    function hasPermission(address user, address insuranceCompany) external view returns (bool) {
        return userPermissions[user][insuranceCompany];
    }
    
    /**
     * @notice Revoke permission from insurance company
     */
    function revokePermission(address insuranceCompany) external {
        userPermissions[msg.sender][insuranceCompany] = false;
    }
}