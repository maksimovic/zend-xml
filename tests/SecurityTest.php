<?php

use PHPUnit\Framework\TestCase;

class Zend_Xml_SecurityTest extends TestCase
{
    public function testScanForXEE(): void
    {
        $xml = <<<XML
<?xml version="1.0"?>
<!DOCTYPE results [<!ENTITY harmless "completely harmless">]>
<results>
    <result>This result is &harmless;</result>
</results>
XML;

        $this->expectException(Zend_Xml_Exception::class);
        $result = Zend_Xml_Security::scan($xml);
    }

    public function testScanForXXE(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'Zend_XML_Security');
        file_put_contents($file, 'This is a remote content!');
        $xml = <<<XML
<?xml version="1.0"?>
<!DOCTYPE root
[
<!ENTITY foo SYSTEM "file://$file">
]>
<results>
    <result>&foo;</result>
</results>
XML;

        try {
            $result = Zend_Xml_Security::scan($xml);
        } catch (Zend_Xml_Exception $e) {
            unlink($file);
            $this->assertStringContainsString('ENTITY', $e->getMessage());
            return;
        }

        $this->fail('An expected exception has not been raised.');
    }

    public function testScanSimpleXmlResult(): void
    {
        $result = Zend_Xml_Security::scan($this->getXml());
        $this->assertInstanceOf(SimpleXMLElement::class, $result);
        $this->assertEquals('test', (string) $result->result);
    }

    public function testScanDom(): void
    {
        $dom = new DOMDocument('1.0');
        $result = Zend_Xml_Security::scan($this->getXml(), $dom);
        $this->assertInstanceOf(DOMDocument::class, $result);
        $node = $result->getElementsByTagName('result')->item(0);
        $this->assertEquals('test', $node->nodeValue);
    }

    public function testScanInvalidXml(): void
    {
        $xml = <<<XML
<foo>test</bar>
XML;

        $result = Zend_Xml_Security::scan($xml);
        $this->assertFalse($result);
    }

    public function testScanInvalidXmlDom(): void
    {
        $xml = <<<XML
<foo>test</bar>
XML;

        $dom = new DOMDocument('1.0');
        $result = Zend_Xml_Security::scan($xml, $dom);
        $this->assertFalse($result);
    }

    public function testScanFile(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'Zend_XML_Security');
        file_put_contents($file, $this->getXml());

        $result = Zend_Xml_Security::scanFile($file);
        $this->assertInstanceOf(SimpleXMLElement::class, $result);
        $this->assertEquals('test', (string) $result->result);
        unlink($file);
    }

    public function testScanXmlWithDTD(): void
    {
        $xml = <<<XML
<?xml version="1.0"?>
<!DOCTYPE results [
<!ELEMENT results (result+)>
<!ELEMENT result (#PCDATA)>
]>
<results>
    <result>test</result>
</results>
XML;

        $dom = new DOMDocument('1.0');
        $result = Zend_Xml_Security::scan($xml, $dom);
        $this->assertInstanceOf(DOMDocument::class, $result);
        $this->assertTrue($result->validate());
    }

    protected function getXml(): string
    {
        return <<<XML
<?xml version="1.0"?>
<results>
    <result>test</result>
</results>
XML;
    }
}
