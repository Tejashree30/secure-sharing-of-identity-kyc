pragma solidity >= 0.8.11 <= 0.8.11;

contract KYCContract {
    string public user_registration;
    string public kyc;
    
       
    //call this function to register user details data to Blockchain
    function setSignup(string memory ur) public {
       user_registration = ur;	
    }
   //get register details
    function getSignup() public view returns (string memory) {
        return user_registration;
    }

    //call this function to save KYC details in Blockchain
    function setKYC(string memory ky) public {
       kyc = ky;	
    }
   //get KYC details
    function getKYC() public view returns (string memory) {
        return kyc;
    }

   constructor() public {
        user_registration="";
	kyc="";
    }
}