import base
import codex
import exceptions
import xml_render

class Processor(base.Processor):
    """
        Apache 2.2 mod_shib2.
    """

    ASSERTION = (
        '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
                'ID="${ASSERTION_ID}" '
                'IssueInstant="${ISSUE_INSTANT}" '
                'Version="2.0">'
            '<saml:Issuer>${ISSUER}</saml:Issuer>'
            '${ASSERTION_SIGNATURE}'
            '${SUBJECT_STATEMENT}'
            '<saml:Conditions NotBefore="${NOT_BEFORE}" NotOnOrAfter="${NOT_ON_OR_AFTER}">'
            '</saml:Conditions>'
            '<saml:AuthnStatement AuthnInstant="${AUTH_INSTANT}"'
                '>'
                '<saml:AuthnContext>'
                    '<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>'
                '</saml:AuthnContext>'
            '</saml:AuthnStatement>'
            '${ATTRIBUTE_STATEMENT}'
        '</saml:Assertion>'
    )

    def _decode_request(self):
        """
            Decode ?SAMLRequest=... redirected by Apache.
        """
        
        # base64-encoded gzip'd XML
        self._request_xml = codex.decode_base64_and_inflate(self._saml_request)
 
    def _validate_request(self):
        """
            Validate the request parameters.

            Raises CannotHandleAssertion.
        """
        acs_url = self._request_params['ACS_URL']

        for name, sp_config in saml2idp_metadata.SAML2IDP_REMOTES.items():
            if acs_url == sp_config['acs_url']:
                pass
            elif 'acs_url_glob' in sp_config and fnmatch(acs_url, sp_config['acs_url_glob']) :
                pass
            else :
                continue

            self._sp_config = sp_config
            return

        raise exceptions.CannotHandleAssertion("Could not find ACS url '%s' in SAML2IDP_REMOTES setting." % acs_url)
   
    def _build_assertion(self):
        """
            Pass through attributes from user to be included in response SAL Assertion.
        """

        super(Processor, self)._build_assertion()

        self._assertion_params.update({
            'ATTRIBUTES':   { 'IsTrue': "FileNotFound" },
        })

    def _format_assertion(self):
        """
            Build POST XML SAMLResponse to send to Apache.
        """
        self._assertion_xml = xml_render._get_assertion_xml(self.ASSERTION, parameters, signed=True)
