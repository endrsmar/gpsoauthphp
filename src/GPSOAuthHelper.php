<?php

	namespace GPSOAuthPHP;
	
	/**
	* Encapsulates supporting functions for GPSOAuth class
	* @package GPSOAuthPHP
	*/
	class GPSOAuthHelper {
		/**
		* Takes 4 bytes from string and converts them into integer
		* @param $source string
		* @param $offset int
		* @return int
		*/
		public static function ByteStringToInt32($source, $offset = 0){
			return (ord($source[$offset])<<24) + (ord($source[$offset+1])<<16) + (ord($source[$offset+2])<<8) + ord($source[$offset+3]);
		}
		
		/**
		* Parses base64 string into RSA key
		* @param $key string
		* @return array
		*/
		public static function Base64ToRSAKey($key){
			$decoded = base64_decode($key);
			$modLenght = GPSOAuthHelper::ByteStringToInt32($decoded);
			$expLenght = GPSOauthHelper::ByteStringToInt32($decoded, 4 + $modLenght);
			$mod = substr($decoded, 4, $modLenght);
			$exp = substr($decoded, 8 + $modLenght, $expLenght);
			return ['modulus' => $mod, 'exponent' => $exp];
		}
		
		/**
		* Parses response from auth service
		* @param $response string
		* @return array
		*/
		public static function ParseAuthResponse($response){
			$result = [];
			foreach (explode("\n", $response) as $line){
				if (!strlen($line)) continue;
				$kvp = explode('=', $line);
				$result[$kvp[0]] = $kvp[1];
			}
			return $result;
		}
		
		/**
		* Composes key into struct
		* @param $key array
		* @return string
		*/
		public static function KeyToStruct(array $key){
			return hex2bin('00000080'.bin2hex($key['modulus']).'00000003'.bin2hex($key['exponent']));
		}
		
		/**
		* Creates signature from email, password and RSA key
		* @param $email string
		* @param $password string
		* @param $pemKey string
		* @param $rsaKey array
		* @return string
		*/
		public static function CreateSignature($email, $password, $pemKey, $rsaKey){
			$encrypted = '';
			openssl_public_encrypt($email.chr(0).$password, $encrypted, $pemKey, OPENSSL_PKCS1_OAEP_PADDING);
			$hash = substr(sha1(self::KeyToStruct($rsaKey), true), 0, 4);
			return self::URLSafeBase64(chr(0).$hash.$encrypted);
		}
		
		/**
		* Encodes input string to URL-safe base64
		* @param $input string
		* @return string
		*/
		public static function URLSafeBase64($input){
			return strtr(base64_encode($input), ['+' => '-', '/' => '_']);
		}
	}