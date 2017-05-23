package org.jscep.util;

import static org.junit.Assert.assertEquals;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Test;

public final class X500UtilsTest {
    @Test
    public void testIssue70() throws Exception {
        // This is the original test string from issue 70.
        String dn = "CN=CA ONE,OU=Test CA,DC=OpenXPKI,DC=ORG";
        
        // This is the minimum test case that occurs in the SCEP transaction
        // Principal is typically created by end-user
        X500Principal principal = new X500Principal(dn);
        assertEquals("Principal name is not equal", dn, principal.getName());
        
        // jscep client encodes using BC encoding mechanism
        byte[] encoded = new X500Name(principal.getName()).getEncoded();
        // This simulates what _ought_ to happen in a server environment.
        // It may be the case that the name is being decoded and the order changed.
        X500Name name = X500Name.getInstance(encoded);
        
        assertEquals("Distinguished name is not equal", dn, name.toString());
    }
}
