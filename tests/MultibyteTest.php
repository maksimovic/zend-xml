<?php

use PHPUnit\Framework\TestCase;

class Zend_Xml_MultibyteTest extends TestCase
{
    public static function multibyteEncodings(): array
    {
        return array(
            'UTF-16LE' => array('UTF-16LE', pack('CC', 0xff, 0xfe), 3),
            'UTF-16BE' => array('UTF-16BE', pack('CC', 0xfe, 0xff), 3),
            'UTF-32LE' => array('UTF-32LE', pack('CCCC', 0xff, 0xfe, 0x00, 0x00), 4),
            'UTF-32BE' => array('UTF-32BE', pack('CCCC', 0x00, 0x00, 0xfe, 0xff), 4),
        );
    }

    public function getXmlWithXXE(): string
    {
        return <<<XML
<?xml version="1.0" encoding="{ENCODING}"?>
<!DOCTYPE methodCall [
  <!ENTITY pocdata SYSTEM "file:///etc/passwd">
]>
<methodCall>
    <methodName>retrieved: &pocdata;</methodName>
</methodCall>
XML;
    }

    public function invokeHeuristicScan(string $xml): void
    {
        Zend_Xml_TestAsset_Security::heuristicScan($xml);
    }

    /**
     * @dataProvider multibyteEncodings
     */
    public function testDetectsMultibyteXXEVectorsUnderFPMWithEncodedStringMissingBOM(string $encoding, string $bom, int $bomLength): void
    {
        $xml = $this->getXmlWithXXE();
        $xml = str_replace('{ENCODING}', $encoding, $xml);
        $xml = iconv('UTF-8', $encoding, $xml);
        $this->assertNotSame(0, strncmp($xml, $bom, $bomLength));
        $this->expectException(Zend_Xml_Exception::class);
        $this->expectExceptionMessage('ENTITY');
        $this->invokeHeuristicScan($xml);
    }

    /**
     * @dataProvider multibyteEncodings
     */
    public function testDetectsMultibyteXXEVectorsUnderFPMWithEncodedStringUsingBOM(string $encoding, string $bom): void
    {
        $xml  = $this->getXmlWithXXE();
        $xml  = str_replace('{ENCODING}', $encoding, $xml);
        $orig = iconv('UTF-8', $encoding, $xml);
        $xml  = $bom . $orig;
        $this->expectException(Zend_Xml_Exception::class);
        $this->expectExceptionMessage('ENTITY');
        $this->invokeHeuristicScan($xml);
    }

    public function getXmlWithoutXXE(): string
    {
        return <<<XML
<?xml version="1.0" encoding="{ENCODING}"?>
<methodCall>
    <methodName>retrieved: &pocdata;</methodName>
</methodCall>
XML;
    }

    /**
     * @dataProvider multibyteEncodings
     */
    public function testDoesNotFlagValidMultibyteXmlAsInvalidUnderFPM(string $encoding): void
    {
        $xml = $this->getXmlWithoutXXE();
        $xml = str_replace('{ENCODING}', $encoding, $xml);
        $xml = iconv('UTF-8', $encoding, $xml);
        try {
            $result = $this->invokeHeuristicScan($xml);
            $this->assertNull($result);
        } catch (\Exception $e) {
            $this->fail('Security scan raised exception when it should not have');
        }
    }

    /**
     * @dataProvider multibyteEncodings
     */
    public function testDetectsXXEWhenXMLDocumentEncodingDiffersFromFileEncoding(string $encoding, string $bom): void
    {
        $xml = $this->getXmlWithXXE();
        $xml = str_replace('{ENCODING}', 'UTF-8', $xml);
        $xml = iconv('UTF-8', $encoding, $xml);
        $xml = $bom . $xml;
        $this->expectException(Zend_Xml_Exception::class);
        $this->expectExceptionMessage('ENTITY');
        $this->invokeHeuristicScan($xml);
    }
}
