<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <!-- <xsl:strip-space elements="*"/> -->
    <xsl:output omit-xml-declaration="no" indent="yes"/>
   <!-- <xsl:template
        match="@*|text()|processing-instruction()|comment()">
        <xsl:copy>
            <xsl:apply-templates
                select="@*|text()|processing-instruction()|comment()"/>
            <!-\- select="*|@*|text()|processing-instruction()|comment()"/-\->
        </xsl:copy>
    </xsl:template>-->
    <xsl:template
        match="*">
        <xsl:element
            name="{local-name()}"
            namespace="{namespace-uri()}">
            <xsl:copy-of select="@*"/>
            <xsl:apply-templates/>
            <!--
            <xsl:for-each select="@*">
                <!-\- Remove attribute prefix.  -\->
                <xsl:attribute name="{local-name()}">
                    <xsl:value-of select="."/>
                </xsl:attribute>
            </xsl:for-each>
            -->
        </xsl:element>
    </xsl:template>
    <xsl:template
        match="@*|text()">
        <xsl:copy>
            <xsl:apply-templates
                select="@*|node()|text()"/>
        </xsl:copy>
    </xsl:template>
</xsl:stylesheet>
