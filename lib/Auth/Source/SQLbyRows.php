<?php

class sspmod_authsqlbyrows_Auth_Source_SQLbyRows extends sspmod_core_Auth_UserPassBase {


	private $dsn;

	private $username;

	private $password;

	private $query;

	public function __construct($info, $config) {
		assert('is_array($info)');
		assert('is_array($config)');
		// Call the parent constructor first, as required by the interface
		parent::__construct($info, $config);
		// Make sure that all required parameters are present.
		foreach (array('dsn', 'username', 'password', 'query') as $param) {
			if (!array_key_exists($param, $config)) {
				throw new Exception('Missing required attribute \'' . $param .
					'\' for authentication source ' . $this->authId);
			}
			if (!is_string($config[$param])) {
				throw new Exception('Expected parameter \'' . $param .
					'\' for authentication source ' . $this->authId .
					' to be a string. Instead it was: ' .
					var_export($config[$param], TRUE));
			}
		}
		$this->dsn = $config['dsn'];
		$this->username = $config['username'];
		$this->password = $config['password'];
		$this->query = $config['query'];
	}

	private function connect() {
		try {
			$db = new PDO($this->dsn, $this->username, $this->password);
		} catch (PDOException $e) {
			throw new Exception('sqlauth:' . $this->authId . ': - Failed to connect to \'' .
				$this->dsn . '\': '. $e->getMessage());
		}
		$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		$driver = explode(':', $this->dsn, 2);
		$driver = strtolower($driver[0]);
		/* Driver specific initialization. */
		switch ($driver) {
		case 'mysql':
			/* Use UTF-8. */
			$db->exec("SET NAMES 'utf8'");
			break;
		case 'pgsql':
			/* Use UTF-8. */
			$db->exec("SET NAMES 'UTF8'");
			break;
		}
		return $db;
	}

	protected function login($username, $password) {
		assert('is_string($username)');
		assert('is_string($password)');

		$db = $this->connect();

		try {
			$sth = $db->prepare($this->query);
		} catch (PDOException $e) {
			throw new Exception('sqlauth:' . $this->authId .
				': - Failed to prepare query: ' . $e->getMessage());
		}

		try {
			$res = $sth->execute(array('username' => $username, 'password' => $password));
		} catch (PDOException $e) {
			throw new Exception('sqlauth:' . $this->authId .
				': - Failed to execute query: ' . $e->getMessage());
		}

		try {
			$data = $sth->fetchAll(PDO::FETCH_ASSOC);
		} catch (PDOException $e) {
			throw new Exception('sqlauth:' . $this->authId .
				': - Failed to fetch result set: ' . $e->getMessage());
		}

		SimpleSAML_Logger::info('sqlauth:' . $this->authId . ': Got ' . count($data) .
			' rows from database');

		if (count($data) === 0) {
			/* No rows returned - invalid username/password. */
			SimpleSAML_Logger::error('sqlauth:' . $this->authId .
				': No rows in result set. Probably wrong username/password.');
			throw new SimpleSAML_Error_Error('WRONGUSERPASS');
		}

		$attributes = array();
		foreach ($data as $row) {

			$name = $row['_key'];
			$value  = $row['_value'];

			if ($value === null || $name == null) {
				continue;
			}			

			if (!array_key_exists($name, $attributes)) {
				$attributes[$name] = array();
			}

			$value = (string)$value;

			if (in_array($value, $attributes[$name], true)) {
				/* Value already exists in attribute. */
				continue;
			}

			$attributes[$name][] = $value;
		}

		SimpleSAML_Logger::info('sqlauth:' . $this->authId . ': Attributes: ' .
			implode(',', array_keys($attributes)));

		return $attributes;
	}

}
