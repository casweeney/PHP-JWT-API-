<?php
	class Api extends Rest {
		public $dbConn;
		public function __construct() {
			parent::__construct();
			$db = new DbConnect;
			$this->dbConn = $db->connect();
		}

		public function generateToken() {
			$email = $this->validateParameter('email', $this->param['email'], STRING);
			$pass = $this->validateParameter('pass', $this->param['pass'], STRING);

			$stmt = $this->dbConn->prepare("SELECT * FROM users WHERE email = :email AND password = :pass");
			$stmt->bindParam(":email", $email);
			$stmt->bindParam(":pass", $pass);
			$stmt->execute();

			$user = $stmt->fetch(PDO::FETCH_ASSOC);
			if(!is_array($user)){
				$this->returnResponse(INVALID_USER_PASS, 'Email or Passord is incorrect.');
			}
		}
	}
?>