<?php

set_time_limit(0);
ini_set('max_execution_time', 0);

final class NetCupDns
{
    const EXTERNAL_REFERENCE_DNS_SERVER = '8.8.8.8';
    const RECORD_NAME_CHALLENGE = '_acme-challenge';

    const NETCUP_ENDPOINT = 'https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON';

    private $netCupApiKey;
    private $netCupApiPw;
    private $netCupCustomerId;

    /**
     * @param string $netCupApiKey
     * @param string $netCupApiPw
     * @param string $netCupCustomerId
     */
    public function __construct($netCupApiKey, $netCupApiPw, $netCupCustomerId)
    {
        $this->netCupApiKey = $netCupApiKey;
        $this->netCupApiPw = $netCupApiPw;
        $this->netCupCustomerId = $netCupCustomerId;
    }

    /**
     * @return string
     * @throws Exception
     */
    private function login()
    {
        $loginData = [
            'action' => 'login',
            'param' => [
                'apipassword' => $this->netCupApiPw,
            ]
        ];
        return  $this->sendRequest($loginData)['responsedata']['apisessionid'];
    }

    /**
     * @param string $session
     * @return bool
     * @throws Exception
     */
    private function logout($session)
    {
        $logoutData = [
            'action' => 'logout',
            'param' => [
                'apisessionid' => $session,
            ]
        ];
        $response = $this->sendRequest($logoutData);
        return $response['status'] === 'success';
    }

    /**
     * @param string $domain
     * @param string $filterType
     * @return array
     * @throws Exception
     */
    private function getDNSRecords($domain, $filterType = '')
    {
        $session = $this->login();
        $data = [
            'action' => 'infoDnsRecords',
            'param' => [
                'domainname' => $domain,
                'apisessionid' => $session,
            ]
        ];
        $dnsRecords = $this->sendRequest($data)['responsedata']['dnsrecords'];
        $this->logout($session);
        return $this->filterDNSRecordsForType($dnsRecords, $filterType);
    }

    /**
     * @param string $domain
     * @return array
     * @throws Exception
     */
    private function getAllExistingChallengesFromDomain($domain)
    {
        $existingRecords = $this->getDNSRecords($domain, 'txt');
        return $this->filterChallengesFromRecords($existingRecords);
    }

    /**
     * @param array $records
     */
    private function filterChallengesFromRecords($records)
    {
        $existingChallenges = [];
        foreach ($records as $record) {
            $name = $record['hostname'];
            if ($name === self::RECORD_NAME_CHALLENGE) {
                $existingChallenges[] = $record;
            }
        }

        return $existingChallenges;
    }

    /**
     * @param string $domain
     * @param string $challenge
     * @return bool
     * @throws Exception
     */
    private function isChallengeExists($domain, $challenge)
    {
        $existingRecords = $this->getAllExistingChallengesFromDomain($domain);
        return !empty($this->lookupChallengeInRecords($existingRecords, $challenge));
    }

    /**
     * @param array $records
     * @param string $challenge
     * @return array
     */
    private function lookupChallengeInRecords($records, $challenge)
    {
        foreach ($records as $record) {
            $name = $record['hostname'];
            $value = $record['destination'];
            if ($name === self::RECORD_NAME_CHALLENGE && $value === $challenge) {
                return $record;
            }
        }

        return [];
    }

    /**
     * @param array $records
     * @param string $domain
     * @return array
     * @throws Exception
     */
    private function updateDnsRecords($records, $domain)
    {
        if (empty($records)) {
            return $this->getDNSRecords($domain);
        }

        $session = $this->login();
        $data = [
            'action' => 'updateDnsRecords',
            'param' => [
                'domainname' => $domain,
                'apisessionid' => $session,
                'dnsrecordset' => [
                    'dnsrecords' => array_values($records)
                ]
            ]
        ];
        $result = $this->sendRequest($data)['responsedata']['dnsrecords'];
        $this->logout($session);

        return $result;
    }

    /**
     * @param string $domain
     * @param string $challenge
     * @return bool
     * @throws Exception
     */
    public function addChallengeToDomain($domain, $challenge)
    {
        if ($this->isChallengeExists($domain, $challenge)) {
            return true;
        }
        $this->output('add challenge to DNS server');
        $records = $this->updateDnsRecords([
            [
                'id' => '',
                'hostname' => self::RECORD_NAME_CHALLENGE,
                'type' => 'TXT',
                'priority' => '',
                'destination' => $challenge,
                'deleterecord' => false,
                'state' => 'yes'
            ]
        ], $domain);
        return !empty($this->lookupChallengeInRecords($this->filterDNSRecordsForType($records, 'txt'), $challenge));
    }

    /**
     * @param string $domain
     * @throws Exception
     */
    public function removeAllChallengesFromDomain($domain)
    {
        $this->output('remove all challenges from DNS server');
        $existingChallenges = $this->getAllExistingChallengesFromDomain($domain);
        if (empty($existingChallenges)) {
            return true;
        }

        $deleteRecords = [];
        foreach ($existingChallenges as $record) {
            $copy = $record;
            $copy['deleterecord'] = true;
            $deleteRecords[] = $copy;
        }
        $recordsLeft = $this->updateDnsRecords($deleteRecords, $domain);
        return empty($this->filterChallengesFromRecords($recordsLeft));
    }

    /**
     * @param string $msg
     */
    private function output($msg)
    {
        echo date("H:i:s") . '[HOOK]: ' . $msg . PHP_EOL;
    }

    /**
     * @param array $records
     * @param string $type
     * @return array
     */
    private function filterDNSRecordsForType($records, $type)
    {
        if ($type !== '') {
            $filteredRecords = [];
            $lookupType = strtolower($type);
            foreach ($records as $record) {
                $recordType = strtolower($record['type']);
                if ($recordType === $lookupType) {
                    $filteredRecords[] = $record;
                }
            }
            return $filteredRecords;
        }

        return $records;
    }

    /**
     * @param string $domain
     * @param string $challenge
     * @param int $timeout
     */
    public function waitUntilDNSChallengeIsPropagated($domain, $challenge, $timeout)
    {
        $found = false;
        $maxExecTime = time() + $timeout;
        while (true) {
            $this->output('check if challenge is propagated');
            if ($this->checkGoogleDNSForChallenge($domain, $challenge)) {
                $found = true;
                break;
            }

            if ($maxExecTime < time()) {
                break;
            }
            sleep(10);
        }

        return $found;
    }

    /**
     * @param string $domain
     * @param string $challenge
     * @return bool
     */
    private function checkGoogleDNSForChallenge($domain, $challenge)
    {
        $challengeDomain = self::RECORD_NAME_CHALLENGE . '.' . $domain . '.';
        $command = 'dig -t TXT '. $challengeDomain .' @'. self::EXTERNAL_REFERENCE_DNS_SERVER .' +noall +answer +short | tr -d \'"\'';
        $lines = [];
        exec($command, $lines);
        return in_array($challenge, $lines, true);
    }

    /**
     * @param array $data
     * @return array
     * @throws Exception
     */
    private function sendRequest(array $data)
    {
        // add credentials
        $data['param']['apikey'] = $this->netCupApiKey;
        $data['param']['customernumber'] = $this->netCupCustomerId;


        $data['param']['clientrequestid'] = strtolower($data['action']).md5(serialize($data));
        $jsonData = json_encode($data);
        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => self::NETCUP_ENDPOINT,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => "",
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 0,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => "POST",
            CURLOPT_POSTFIELDS => $jsonData,
            CURLOPT_HTTPHEADER => ["Content-Type: application/json"],
        ));
        $response = curl_exec($curl);
        $responseData = json_decode($response, true);
        if ($responseData['clientrequestid'] !== $data['param']['clientrequestid']) {
            throw new Exception('mismatch client request ID, corrupt response');
        }
        if ($responseData['status'] !== 'success') {
            print_r($data);
            print_r($jsonData);
            throw new Exception('failed request: ' . PHP_EOL . print_r($responseData, true));
        }
        curl_close($curl);
        return $responseData;
    }
}

$data = file_get_contents(__DIR__.'/credentials');
$credentials = unserialize(base64_decode($data));

$domain = $argv[1];
$challenge = $argv[2];
$type = $argv[3];

$netCupDns = new NetCupDns($credentials['key'], $credentials['pw'], $credentials['id']);
if ($type === 'update') {
    $netCupDns->addChallengeToDomain($domain, $challenge);
    $netCupDns->waitUntilDNSChallengeIsPropagated($domain, $challenge, 1800);
} elseif ($type === 'clean') {
    $netCupDns->removeAllChallengesFromDomain($domain);
}
