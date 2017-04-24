<?php

class sspmod_sqlauth_Auth_Source_SQLbyRows extends sspmod_sqlauth_Auth_Source_SQL {

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
