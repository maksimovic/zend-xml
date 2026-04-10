<?php

class Zend_Xml_TestAsset_Security extends Zend_Xml_Security
{
    /**
     * Override heuristic scan to make it public for testing.
     *
     * @param string $xml
     * @throws Zend_Xml_Exception If entity expansion or external entity declaration was discovered.
     */
    public static function heuristicScan($xml): void
    {
        parent::heuristicScan($xml);
    }
}
