<?php

use Rephlux\SpfResolver\SpfResolver;

class SpfResolverTest extends PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function it_loads_ip_address_from_dns_records_with_spf_includes()
    {
        $spf = $this->getSpfMockObject();

        $spf->expects($this->at(0))
            ->method('getDnsRecord')
            ->will($this->returnValue(
                [
                    [
                        'host'    => 'example.com',
                        'type'    => 'TXT',
                        'txt'     => 'v=spf1 mx include:spf.example.com ip4:83.138.66.153 -all',
                        'entries' => [
                            'v=spf1 mx include:spf.example.com ip4:83.138.66.153 -all'
                        ],
                        'class'   => 'IN',
                        'ttl'     => ''
                    ]
                ]
            )
            );

        $spf->expects($this->at(1))
            ->method('getDnsRecord')
            ->will($this->returnValue(
                [
                    [
                        'host'    => 'example.com',
                        'type'    => 'TXT',
                        'txt'     => 'v=spf1 mx ip4:83.138.66.154 ip4:83.138.66.155 -all',
                        'entries' => [
                            'v=spf1 mx ip4:83.138.66.154 ip4:83.138.66.155 -all'
                        ],
                        'class'   => 'IN',
                        'ttl'     => ''
                    ]
                ]
            )
            );

        $ipAddresses = $spf->resolveDomain('example.com');

        $this->assertEquals(['83.138.66.153', '83.138.66.154', '83.138.66.155'], $ipAddresses);
    }

    /**
     * @test
     */
    public function it_loads_ip_address_from_dns_records_with_spf_redirect()
    {
        $spf = $this->getSpfMockObject();

        $spf->expects($this->at(0))
            ->method('getDnsRecord')
            ->will($this->returnValue(
                [
                    [
                        'host'    => 'example.com',
                        'type'    => 'TXT',
                        'txt'     => 'v=spf1 redirect=_spf.example.com',
                        'entries' => [
                            'v=spf1 redirect=_spf.example.com'
                        ],
                        'class'   => 'IN',
                        'ttl'     => ''
                    ]
                ]
            )
            );

        $spf->expects($this->at(1))
            ->method('getDnsRecord')
            ->will($this->returnValue(
                [
                    [
                        'host'    => '_spf.example.com',
                        'type'    => 'TXT',
                        'txt'     => 'v=spf1 mx ip4:83.138.66.154 -all',
                        'entries' => [
                            'v=spf1 mx ip4:83.138.66.154 -all'
                        ],
                        'class'   => 'IN',
                        'ttl'     => ''
                    ]
                ]
            )
            );

        $ipAddresses = $spf->resolveDomain('example.com');

        $this->assertEquals(['83.138.66.154'], $ipAddresses);
    }

    /**
     * @test
     */
    public function it_fails_loading_ip_address_from_dns_records_with_spf_includes()
    {
        $spf = $this->getSpfMockObject();

        $spf->expects($this->once())
            ->method('getDnsRecord')
            ->will($this->returnValue(
                [
                    [
                        'host'    => 'example.com',
                        'type'    => 'TXT',
                        'txt'     => 'v=spf1 mx require:spf.example.com ip4:83.138.66.153 -all',
                        'entries' => [
                            'v=spf1 mx require:spf.example.com ip4:83.138.66.153 -all'
                        ],
                        'class'   => 'IN',
                        'ttl'     => ''
                    ]
                ]
            )
            );

        $ipAddresses = $spf->resolveDomain('example.com');

        $this->assertEquals(['83.138.66.153'], $ipAddresses);
    }

    /**
     * @test
     */
    public function it_loads_ip_address_from_dns_records()
    {
        $spf = $this->getSpfMockObject();

        $spf->expects($this->once())
            ->method('getDnsRecord')
            ->will($this->returnValue(
                [
                    [
                        'host'    => 'example.com',
                        'type'    => 'TXT',
                        'txt'     => 'v=spf1 mx ip4:83.138.66.153 -all',
                        'entries' => [
                            'v=spf1 mx ip4:83.138.66.153 -all'
                        ],
                        'class'   => 'IN',
                        'ttl'     => ''
                    ]
                ]
            )
            );

        $ipAddresses = $spf->resolveDomain('example.com');

        $this->assertEquals(['83.138.66.153'], $ipAddresses);
    }

    /**
     * @test
     */
    public function it_loads_ip_address_from_multiple_txt_records()
    {
        $spf = $this->getSpfMockObject();

        $spf->expects($this->once())
            ->method('getDnsRecord')
            ->will($this->returnValue(
                [
                    [
                        'host'    => 'example.com',
                        'type'    => 'TXT',
                        'txt'     => 'spf2.0/pra ip4:83.138.66.155 -all',
                        'entries' => [
                            'spf2.0/pra ip4:83.138.66.155 -all'
                        ],
                        'class'   => 'IN',
                        'ttl'     => ''
                    ],
                    [
                        'host'    => 'example.com',
                        'type'    => 'TXT',
                        'txt'     => 'v=spf1 mx ip4:83.138.66.153 -all',
                        'entries' => [
                            'v=spf1 mx ip4:83.138.66.153 -all'
                        ],
                        'class'   => 'IN',
                        'ttl'     => ''
                    ]
                ]
            )
            );

        $ipAddresses = $spf->resolveDomain('example.com');

        $this->assertEquals(['83.138.66.153'], $ipAddresses);
    }

    /**
     * @test
     */
    public function it_fails_loading_invalid_ip_entry_from_dns_record()
    {
        $spf = $this->getSpfMockObject();

        $spf->expects($this->once())
            ->method('getDnsRecord')
            ->will($this->returnValue(
                [
                    [
                        'host'    => 'example.com',
                        'type'    => 'TXT',
                        'txt'     => 'v=spf1 mx ip:83.138.66.153 -all',
                        'entries' => [
                            'v=spf1 mx ip:83.138.66.153 -all'
                        ],
                        'class'   => 'IN',
                        'ttl'     => ''
                    ]
                ]
            )
            );

        $ipAddresses = $spf->resolveDomain('example.com');

        $this->assertEmpty($ipAddresses);
    }

    /**
     * @test
     */
    public function it_fails_resolving_invalid_spf_entry()
    {
        $spf = $this->getSpfMockObject();

        $spf->expects($this->once())
            ->method('getDnsRecord')
            ->will($this->returnValue(
                [
                    [
                        'host'    => 'example.com',
                        'type'    => 'TXT',
                        'txt'     => 'v=test mx ip4:83.138.66.153 -all',
                        'entries' => [
                            'v=test mx ip4:83.138.66.153 -all'
                        ],
                        'class'   => 'IN',
                        'ttl'     => ''
                    ]
                ]
            )
            );

        $ipAddresses = $spf->resolveDomain('example.com');

        $this->assertEmpty($ipAddresses);
    }

    /**
     * @test
     */
    public function it_resets_resolved_ips_after()
    {
        $spf = $this->getSpfMockObject();

        $spf->expects($this->once())
            ->method('getDnsRecord')
            ->will($this->returnValue(
                [
                    [
                        'host'    => 'example.com',
                        'type'    => 'TXT',
                        'txt'     => 'v=spf1 mx ip4:83.138.66.153 -all',
                        'entries' => [
                            'v=spf1 mx ip4:83.138.66.153 -all'
                        ],
                        'class'   => 'IN',
                        'ttl'     => ''
                    ]
                ]
            )
            );

        $ipAddresses = $spf->resolveDomain('example.com');

        $this->assertEquals(['83.138.66.153'], $ipAddresses);

        $spf->resetResolvedIPs();

        $this->assertEmpty($spf->getIpAddresses());
    }

    /**
     * @test
     */
    public function it_fails_loading_dns_records_from_invalid_host()
    {
        $spf = $this->getSpfMockObject();

        $spf->expects($this->once())
            ->method('getDnsRecord')
            ->will($this->returnValue([])
            );

        $ipAddresses = $spf->resolveDomain('example---com');

        $this->assertEquals(false, $ipAddresses);
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|SpfResolver
     */
    public function getSpfMockObject()
    {
        return $this->getMockBuilder(SpfResolver::class)->setMethods(['getDnsRecord'])->getMock();
    }
}
