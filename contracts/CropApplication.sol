// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CropApplication {
    struct Application {
        bytes32 id;
        address ethAddress;
        string status;
        uint midCropAssessmentDate;
        uint harvestDate;
        string cropGrade;
        uint perKgRate;
        bool graded;
        bool rateAssigned;
        uint gradingTimestamp;
        uint rateTimestamp;
        uint quantity; 
    }

    mapping(bytes32 => Application) public cropApplications;
    mapping(address => bytes32) public ethToApplicationId;
    bytes32[] public applicationIds;

    event CropApplicationSubmitted(bytes32 id, address indexed ethAddress, string username, string status);
    event ApplicationStatusUpdated(bytes32 id, address indexed ethAddress, string status);
    event MidCropAssessmentBooked(bytes32 id, address indexed ethAddress, uint assessmentDate);
    event HarvestDateBooked(bytes32 id, address indexed ethAddress, uint harvestDate);
    event CropGraded(bytes32 id, address indexed ethAddress, string grade, uint timestamp);
    event PerKgRateAssigned(bytes32 id, address indexed ethAddress, uint rate,uint quantity, uint timestamp);
    event ApplicationMovedToMidAssessment(bytes32 id, address indexed ethAddress, string status);
    event ApplicationMovedToHarvestStage(bytes32 id, address indexed ethAddress, string status);

    function submitApplication(
        string memory cropName,
        string memory cropType,
        uint sowDate,
        uint harvestDate,
        string memory district,
        string memory username,
        string memory userAddress,
        string memory contactNumber,
        string memory landOwnerName,
        string memory landSurveyNumber
    ) public {
        bytes32 applicationId = keccak256(
            abi.encodePacked(msg.sender, block.timestamp, cropName, district)
        );

        require(cropApplications[applicationId].ethAddress == address(0), "Application ID already exists");

        cropApplications[applicationId] = Application({
            id: applicationId,
            ethAddress: msg.sender,
            status: "Crop Application Submitted successfully",
            midCropAssessmentDate: 0,
            harvestDate: 0,
            cropGrade: "",
            perKgRate: 0,
            graded: false,
            rateAssigned: false,
            gradingTimestamp: 0,
            rateTimestamp: 0,
            quantity: 0
        });

        applicationIds.push(applicationId);
        ethToApplicationId[msg.sender] = applicationId;

        emit CropApplicationSubmitted(applicationId, msg.sender, username, "Crop Application Submitted successfully");
    }

    function getLastApplicationId() public view returns (bytes32) {
        require(applicationIds.length > 0, "No applications found");
        return applicationIds[applicationIds.length - 1];
    }
        // 🔹 New Function: Update Application Status Using Application ID
    function updateApplicationStatus(bytes32 applicationId, string memory _status) public {
        require(cropApplications[applicationId].ethAddress != address(0), "Application does not exist");

        Application storage application = cropApplications[applicationId];
        application.status = _status;

        emit ApplicationStatusUpdated(applicationId, application.ethAddress, _status);
    }


    
    function applicationExistsByAddress(address userAddress) public view returns (bool) {
        bytes32 applicationId = ethToApplicationId[userAddress];
        return cropApplications[applicationId].ethAddress != address(0);
    }

    function acceptApplicationByAddress(address userAddress) public {
        bytes32 applicationId = ethToApplicationId[userAddress];
        require(applicationId != bytes32(0), "No application found");

        Application storage application = cropApplications[applicationId];
        application.status = "Details Verified Successfully";

        emit ApplicationStatusUpdated(applicationId, application.ethAddress, "Details Verified Successfully");
    }

    function updateApplicationStatusByAddress(address userAddress, string memory _status) public {
        bytes32 applicationId = ethToApplicationId[userAddress];
        require(applicationId != bytes32(0), "No application found for this address");

        Application storage application = cropApplications[applicationId];
        application.status = _status;

        emit ApplicationStatusUpdated(applicationId, userAddress, _status);
    }

    // **🔹 Book Mid-Crop Assessment using ETH Address**
    function bookMidCropAssessmentByAddress(address farmer, uint assessmentDate) public {
        bytes32 applicationId = ethToApplicationId[farmer];
        require(applicationId != bytes32(0), "Application does not exist");

        Application storage application = cropApplications[applicationId];

        require(application.midCropAssessmentDate == 0, "Assessment date already booked");
        

        application.midCropAssessmentDate = assessmentDate;

        emit MidCropAssessmentBooked(applicationId, farmer, assessmentDate);
    }

    // **🔹 Book Harvest Date using ETH Address**
    function bookHarvestDateByAddress(address farmer, uint _harvestDate) public {
        bytes32 applicationId = ethToApplicationId[farmer];
        require(applicationId != bytes32(0), "Application does not exist");

        Application storage application = cropApplications[applicationId];

        require(application.harvestDate == 0, "Harvest date already booked");

        application.harvestDate = _harvestDate;

        emit HarvestDateBooked(applicationId, farmer, _harvestDate);
    }

    function gradeCrop(bytes32 applicationId, string memory grade) public {
        require(cropApplications[applicationId].ethAddress != address(0), "Application does not exist");
        Application storage application = cropApplications[applicationId];

        require(!application.graded, "Crop already graded");
        require(keccak256(bytes(grade)) == keccak256(bytes("A")) || 
                keccak256(bytes(grade)) == keccak256(bytes("B")) || 
                keccak256(bytes(grade)) == keccak256(bytes("C")), "Invalid grade");

        application.cropGrade = grade;
        application.graded = true;
        application.gradingTimestamp = block.timestamp;
        application.status = string(abi.encodePacked("Mid Crop Assessment Done Successfully and Grade Given is: ", grade));

        emit CropGraded(applicationId, application.ethAddress, grade, block.timestamp);
    }

    function assignPerKgRate(bytes32 applicationId, uint rate,uint quantity) public {
        require(cropApplications[applicationId].ethAddress != address(0), "Application does not exist");
        Application storage application = cropApplications[applicationId];

        require(application.graded, "Crop must be graded first");
        require(!application.rateAssigned, "Rate already assigned");

        application.perKgRate = rate;
        application.rateAssigned = true;
        application.rateTimestamp = block.timestamp;
        application.quantity = quantity;

        emit PerKgRateAssigned(applicationId, application.ethAddress, rate,quantity, block.timestamp);
    }

    function reduceQuantityByAddress(address farmer, uint amount) public {
    bytes32 applicationId = ethToApplicationId[farmer];
    require(applicationId != bytes32(0), "Application not found");

    Application storage application = cropApplications[applicationId];
    require(application.quantity >= amount, "Not enough quantity available");

    application.quantity -= amount;
}
}

