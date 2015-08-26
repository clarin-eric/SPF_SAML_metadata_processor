<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <xsl:strip-space elements="*"/>
    <xsl:output omit-xml-declaration="no" indent="yes"/>
    <xsl:template
        match="*[self::ds:X509Certificate or self::ds:SignatureValue or self::ds:Modulus or self::ds:Exponent]/text()[normalize-space()]">
        <xsl:value-of
            select="normalize-space()"/>
    </xsl:template>

    <xsl:template
        match="*[self::ds:X509Certificate or self::ds:SignatureValue or self::ds:Modulus or self::ds:Exponent]/text()[not(normalize-space())]"/>

    <xsl:template match="text()">
        <!-- <xsl:value-of select="translate(.,'&#xA;','')"/> -->
        <xsl:value-of select="normalize-space(.)"/>
    </xsl:template>

    <xsl:template
        match="@*|*|processing-instruction()|comment()">
        <xsl:copy>
            <xsl:apply-templates
                select="*|@*|text()|processing-instruction()|comment()"/>
        </xsl:copy>
    </xsl:template>
</xsl:stylesheet>
