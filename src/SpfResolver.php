<?php
/*
 * This file is part of the SpfResolver package.
 *
 * (c) Chris van Daele <engine_no9@gmx.net>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Rephlux\SpfResolver;

/**
 * A Spf Resolver for PHP.
 *
 * This package resolves any ip addresses from a dns record with valid spf entry.
 *
 * @author: Chris van Daele (engine_no9@gmx.net)
 *
 */
class SpfResolver
{
    /**
     * @var array
     */
    protected $ipAddresses = [];

    /**
     * @var string
     */
    protected $spfData;

    /**
     * @var string
     */
    protected static $regexIpAddress = '/ip[4|6]:([\.\/0-9a-z\:]*)/';

    /**
     * @var string
     */
    protected static $regexInclude = '/include:([a-zA-Z\._0-9\-]*)/';

    /**
     * @var string
     */
    protected static $regexRedirect = '/redirect=([a-zA-Z\._0-9\-]*)/';

    /**
     * Load ip addresses from a spf record for a specific hostname.
     *
     * @param string $hostname
     *
     * @return array
     */
    public function resolveDomain($hostname)
    {
        $dnsData = $this->getDnsRecord($hostname);

        if ($this->hasDnsData($dnsData) === false) {
            return false;
        }

        $this->spfData = $this->extractSpfRecord($dnsData);

        if ($this->hasValidSpfData($this->spfData) === false) {
            return $this->getIpAddresses();
        }

        return $this->extractIpAdresses()
                    ->followRedirects()
                    ->extractInclude()
                    ->getIpAddresses();
    }

    /**
     * Load the dns record from a hostname.
     *
     * @param string $hostname
     * @codeCoverageIgnore
     *
     * @return array
     */
    public function getDnsRecord($hostname)
    {
        return dns_get_record($hostname, DNS_TXT);
    }

    /**
     * Get a unique list of all the resolved ip addresses.
     *
     * @return array
     */
    public function getIpAddresses()
    {
        return array_values(array_unique($this->ipAddresses));
    }

    /**
     * Get the spf data.
     *
     * @return mixed
     */
    public function getSpfData()
    {
        return $this->spfData;
    }

    /**
     * Resets the internal ipAddresses array to an empty array
     */
    public function resetResolvedIPs()
    {
        $this->ipAddresses = [];
    }

    /**
     * Detect if a specified dns data is valid.
     *
     * @param array $dnsData
     *
     * @return bool
     */
    protected function hasDnsData(array $dnsData)
    {
        return ($dnsData && !empty(array_column($dnsData, 'txt')));
    }

    /**
     * Detect if specified dns data contains valid spf data.
     *
     * @param string $dnsData
     *
     * @return bool|int
     */
    protected function hasValidSpfData($dnsData)
    {
        return strpos($dnsData, 'spf1');
    }

    /**
     * Extract ip addresses from dns data.
     *
     * @return $this
     */
    protected function extractIpAdresses()
    {
        $this->ipAddresses = array_merge($this->ipAddresses,
            $this->extractDnsData(self::$regexIpAddress, $this->getSpfData())
        );

        return $this;
    }

    /**
     * Follow the redirects to other ip adresses.
     *
     * @return $this
     */
    protected function followRedirects()
    {
        $this->ipAddresses = $this->mergeIpAddresses(
            $this->getIpAddresses(),
            $this->extractDnsData(self::$regexRedirect, $this->getSpfData())
        );

        return $this;
    }

    /**
     * Extract spf includes from dns data.
     *
     * @return $this
     */
    protected function extractInclude()
    {
        $this->ipAddresses = $this->mergeIpAddresses(
            $this->getIpAddresses(),
            $this->extractDnsData(self::$regexInclude, $this->getSpfData())
        );

        return $this;
    }

    /**
     * Merge resolved ip addresses.
     *
     * @param array $ipAddresses
     * @param array $spfData
     *
     * @return array
     */
    protected function mergeIpAddresses(array $ipAddresses, array $spfData)
    {
        foreach ($spfData as $spf) {
            $ipAddresses = array_merge($ipAddresses, $this->resolveDomain($spf));
        }

        return $ipAddresses;
    }

    /**
     * Gets the spf data from dns record.
     *
     * @param $dnsData
     *
     * @return mixed
     */
    protected function extractSpfRecord($dnsData)
    {
        $pattern = preg_quote('spf1', '~');
        $data    = array_column($dnsData, 'txt');

        return implode(' ', preg_grep('~' . $pattern . '~', $data));
    }

    /**
     * Extract data with a regular expression from dns data.
     *
     * @param string $regex
     * @param string $dnsData
     *
     * @return array
     */
    protected function extractDnsData($regex, $dnsData)
    {
        preg_match_all($regex, $dnsData, $matches);

        if (!isset($matches[1]) || empty($matches[1])) {
            return [];
        }

        return $matches[1];
    }
}
