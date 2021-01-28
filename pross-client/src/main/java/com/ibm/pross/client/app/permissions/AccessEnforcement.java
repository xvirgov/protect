package com.ibm.pross.client.app.permissions;

import com.ibm.pross.client.app.permissions.AppPermissions.Permissions;
import com.ibm.pross.common.exceptions.http.NotFoundException;
import com.ibm.pross.common.exceptions.http.UnauthorizedException;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class AccessEnforcement {

    // Map of usernames to their associated permissions
    private final ConcurrentMap<String, AppPermissions> permissionMap;

    private final Set<String> knownSecrets;

    public AccessEnforcement(final Map<String, AppPermissions> permissionMap, Set<String> knownSecrets) {
        this.permissionMap = new ConcurrentHashMap<>(permissionMap);
        this.knownSecrets = Collections.unmodifiableSet(knownSecrets);;
    }

    public void enforceAccess(final String username, final String secretName, final Permissions permission)
            throws UnauthorizedException, NotFoundException {

        if (!knownSecrets.contains(secretName))
        {
            throw new NotFoundException();
        }

        if (username == null)
        {
            // Client is anonymous
            throw new UnauthorizedException();
        }

        // Get this client's permissions
        final AppPermissions clientPermissions = this.permissionMap.get(username);

        if (clientPermissions == null) {
            // Client is unknown
            throw new UnauthorizedException();
        } else {
            // Client is known but is not authorized
            if (!clientPermissions.hasPermission(secretName, permission)) {
                throw new UnauthorizedException();
            }
        }
    }

    public Set<String> getKnownSecrets()
    {
        // Not modifiable
        return knownSecrets;
    }

    public Set<String> getKnownUsers()
    {
        return Collections.unmodifiableSet(permissionMap.keySet());
    }

    private static final class DummyAccessEnforcement extends AccessEnforcement {

        public DummyAccessEnforcement() {
            super(Collections.emptyMap(), Collections.emptySet());
        }

        @Override
        public void enforceAccess(final String username, final String secretName, final Permissions permission)
                throws UnauthorizedException {
            // Always allow
        }
    }

    @Deprecated
    public static final AccessEnforcement INSECURE_DUMMY_ENFORCEMENT = new DummyAccessEnforcement();


}
