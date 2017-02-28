<?php

namespace Ondrejnov\EET;

use Ondrejnov\EET\Exceptions\ClientException;
use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class SoapClient extends \SoapClient {

	/** @var string */
	private $key;

	/** @var string */
	private $passphrase;

	/** @var string */
	private $cert;

	/** @var boolean */
	private $traceRequired;

	/** @var float */
	private $connectionStartTime;

	/** @var float */
	private $lastResponseStartTime;

	/** @var float */
	private $lastResponseEndTime;

	/** @var string */
	private $lastRequest;

	private $returnRequest = FALSE;

	/**
	 * @var int timeout in milliseconds
	 */
	private $timeout = 2500;
	/**
	 * @var int connection timeout in milliseconds
	 */
	private $connectTimeout = 2000;

	/**
	 * @var string
	 */
	private $lastResponse;

	/**
	 * @var string
	 */
	private $lastResponseBody;

	/**
	 *
	 * @param string $service
	 * @param string $key
	 * @param string $cert
	 * @param boolean $trace
	 */
	public function __construct($service, $key, $cert, $trace = FALSE, $passphrase = NULL) {
		$this->connectionStartTime = microtime(TRUE);
		parent::__construct($service, array(
			'exceptions' => TRUE,
			'trace' => $trace
		)
		);
		$this->key = $key;
		$this->cert = $cert;
		$this->traceRequired = $trace;
		$this->passphrase = $passphrase;
	}

	public function getXML($request) {

		$doc = new \DOMDocument('1.0');
		$doc->loadXML($request);

		$objWSSE = new WSSESoap($doc);
		$objWSSE->addTimestamp();

		$objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
		if ($this->passphrase) {
			$objKey->passphrase = $this->passphrase;
		}
		$objKey->loadKey($this->key, TRUE);
		$objWSSE->signSoapDoc($objKey, array("algorithm" => XMLSecurityDSig::SHA256));

		$token = $objWSSE->addBinaryToken(file_get_contents($this->cert));
		$objWSSE->attachTokentoSig($token);

		return $objWSSE->saveXML();
	}

	public function getXMLforMethod($method, $data) {
		$this->returnRequest = TRUE;
		$this->$method($data);
		$this->returnRequest = FALSE;
		return $this->lastRequest;
	}

	public function __doRequest($request, $location, $saction, $version, $one_way = NULL) {

		$xml = $this->getXML($request);
		$this->lastRequest = $xml;
		if ($this->returnRequest) {
			return '';
		}

		$this->traceRequired && $this->lastResponseStartTime = microtime(TRUE);

		$response = $this->__doRequestByCurl($xml, $location, $saction, $version);

		$this->traceRequired && $this->lastResponseEndTime = microtime(TRUE);

		return $response;
	}

	/**
	 * @param string $request
	 * @param string $location
	 * @param string $action
	 * @param int    $version
	 * @param bool   $one_way
	 *
	 * @return string|null
	 * @throws ClientException
	 */
	public function __doRequestByCurl($request, $location, $action, $version, $one_way = FALSE)
	{
		$cmd = 'curl ' . $location;

		/** @var $headers array of headers to be sent with request */
		$headers = array(
			'User-Agent: PHP-SOAP',
			'Content-Type: ' . ($version == 2 ? 'application/soap+xml' : 'text/xml') . '; charset=utf-8',
			'SOAPAction: "OdeslaniTrzby"',
			'Content-Length: ' . strlen($request),
		);
		// add headers
		foreach ($headers as $h) {
			$cmd .= ' -H \''.$h.'\'';
		}
		// add POST data
		$cmd .= ' -X POST -d \'' . $request . '\'';

		// execute command using shell
		$response = $body = shell_exec($cmd);
		$this->lastResponse = $response;
		$this->lastResponseBody = $body;

		// Return?
		if ($one_way) {
			return null;
		} else {
			return $body;
		}
	}

	private function __setCurlOptions($curl, array $options)
	{
		foreach ($options as $option => $value) {
			if (false !== curl_setopt($curl, $option, $value)) {
				continue;
			}
			throw new ClientException(
				sprintf('Failed setting CURL option %d (%s) to %s', $option, $this->__getCurlOptionName($option), var_export($value, true))
			);
		}
	}

	private function __curlSetTimeoutOption($options, $milliseconds, $name)
	{
		if ($milliseconds > 0) {
			if (defined("{$name}_MS")) {
				$options[constant("{$name}_MS")] = $milliseconds;
			} else {
				$seconds        = ceil($milliseconds / 1000);
				$options[$name] = $seconds;
			}
			if ($milliseconds <= 1000) {
				$options[CURLOPT_NOSIGNAL] = 1;
			}
		}
		return $options;
	}


	/**
	 *
	 * @return float
	 */
	public function __getLastResponseTime() {
		if (!$this->lastResponseEndTime || !$this->lastResponseStartTime) {
			return NULL;
		}
		return $this->lastResponseEndTime - $this->lastResponseStartTime;
	}

	/**
	 *
	 * @return float
	 */
	public function __getConnectionTime($tillLastRequest = FALSE) {
		return $tillLastRequest ? $this->getConnectionTimeTillLastRequest() : $this->getConnectionTimeTillNow();
	}

	private function getConnectionTimeTillLastRequest() {
		if (!$this->lastResponseEndTime || !$this->connectionStartTime) {
			return NULL;
		}
		return $this->lastResponseEndTime - $this->connectionStartTime;
	}

	private function getConnectionTimeTillNow() {
		if (!$this->connectionStartTime) {
			return NULL;
		}
		return microtime(TRUE) - $this->connectionStartTime;
	}

	/**
	 * @return string
	 */
	public function __getLastRequest() {
		return $this->lastRequest;
	}

	/**
	 * @param int|null $milliseconds timeout in milliseconds
	 */
	public function setTimeout($milliseconds)
	{
		$this->timeout = $milliseconds;
	}
	/**
	 * @return int|null timeout in milliseconds
	 */
	public function getTimeout()
	{
		return $this->timeout;
	}
	/**
	 * @param int|null $milliseconds
	 */
	public function setConnectTimeout($milliseconds)
	{
		$this->connectTimeout = $milliseconds;
	}
	/**
	 * @return int|null
	 */
	public function getConnectTimeout()
	{
		return $this->connectTimeout;
	}

	/**
	 * @return mixed
	 */
	public function __getLastResponse()
	{
		return $this->lastResponse;
	}

	/**
	 * @return mixed
	 */
	public function __getLastResponseBody()
	{
		return $this->lastResponseBody;
	}





}
