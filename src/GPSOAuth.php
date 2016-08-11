<?php
		
	namespace GPSOAuthPHP;
	
	/**
	* Provides means of authenticating against Google Play Services
	* PHP port of https://github.com/simon-weber/gpsoauth
	* @package GPSOAuthPHP
	*/
	class GPSOAuth {
		const _URL = 'https://android.clients.google.com/auth';
		const _AGENT = 'mgr.go/0.0.1';
		const _KEY = 'AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ==';
		
		/**
		* Retreives the RSA PEM key
		* @return string
		*/
		public static function GetPEMKey(){
			return file_get_contents(__DIR__.'/pubkey.pem');
		}
		
		/**
		* Retreives the RSA key
		* @return array
		*/
		public static function GetRSAKey(){
			return GPSOAuthHelper::Base64ToRSAKey(self::_KEY);
		}
		
		public function __construct($email, $password){
			$this->email = $email;
			$this->password = $password;
		}
		
		/**
		* Performs authentication request
		* @param $data array
		* @return array
		*/
		private function authRequest(array $data){
			$curlHandle = curl_init();
			curl_setopt($curlHandle, CURLOPT_URL, self::_URL);
			curl_setopt($curlHandle, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($curlHandle, CURLOPT_FOLLOWLOCATION, true);
			curl_setopt($curlHandle, CURLOPT_POST, 1);
			curl_setopt($curlHandle, CURLOPT_POSTFIELDS, $data);
			curl_setopt($curlHandle, CURLOPT_SSL_VERIFYPEER, 0);
			curl_setopt($curlHandle, CURLOPT_HTTPHEADER, [
				'User-Agent: mgrgo/0.0.1'
			]);
			$result = curl_exec($curlHandle);
			return GPSOAuthHelper::ParseAuthResponse($result);
		}
		
		/**
		* Performs master login
		* @param $service string
		* @param $deviceCountry string
		* @param $operatorCountry string
		* @param $lang string
		* @param $sdkVersion int
		*/
		public function masterLogin($service = 'ac2dm', $deviceCountry = 'us', $operatorCountry = 'us', $lang = 'en', $sdkVersion = 21){
			$signature = GPSOAuthHelper::CreateSignature($this->email, $this->password, self::GetPEMKey(), self::GetRSAKey());
			$data = [
				'accountType' => 'HOSTED_OR_GOOGLE',
				'Email' => $this->email,
				'has_permission' => '1',
				'add_account' => '1',
				'EncryptedPasswd' => $signature,
				'service' => $service,
				'source' => 'android',
				'device_country' => $deviceCountry,
				'operatorCountry' => $operatorCountry,
				'lang' => $lang,
				'sdk_version' => ''.$sdkVersion
			];
			return $this->authRequest($data);
		}
		
		/**
		* Performs OAuth
		* @param $masterToken string
		* @param $service string
		* @param $app string
		* @param $clientSig string
		* @param $deviceCountry string
		* @param $operatorCountry string
		* @param $lang string
		* @param $sdkVersion int
		* @return array
		*/
		public function oAuth($masterToken, $service, $app, $clientSig, $deviceCountry = 'us', $operatorCountry = 'us', $lang = 'en', $sdkVersion = 21){
			$data = [
				'accountType' => 'HOSTED_OR_GOOGLE',
				'Email' => $this->email,
				'has_permission' => '1',
				'EncryptedPasswd' => $masterToken,
				'service' => $service,
				'source' => 'android',
				'app' => $app,
				'client_sig' => $clientSig,
				'device_country' => $deviceCountry,
				'operatorCountry' => $operatorCountry,
				'lang' => $lang,
				'sdk_version' => ''.$sdkVersion
			];
			return $this->authRequest($data);
		}
		
		/**
		* @var string
		*/
		private $email;
		
		/**
		* @var string
		*/
		private $password;
	}