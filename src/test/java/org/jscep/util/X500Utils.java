package org.jscep.util;

import static org.junit.Assert.assertEquals;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.Test;

public final class X500Utils {
    @Test
    public void testIssue70() {
        String dn = "CN=CA ONE,OU=Test CA,DC=OpenXPKI,DC=ORG";
        
        X500Principal principal = new X500Principal(dn);
        X500Name name = new X500Name(principal.getName());
        
        assertEquals("Distinguished name is unchanged", dn, name.toString());
    }
}
