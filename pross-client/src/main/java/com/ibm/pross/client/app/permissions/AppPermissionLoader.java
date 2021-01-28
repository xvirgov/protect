package com.ibm.pross.client.app.permissions;

import com.ibm.pross.client.app.permissions.AppPermissions.Permissions;
import org.ini4j.Profile;
import org.ini4j.Wini;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AppPermissionLoader {

    private static final Logger logger = LogManager.getLogger(AppPermissionLoader.class);

    public static AccessEnforcement loadIniFile(final File iniFile) throws IOException {

        logger.info("Loading client permissions: " + iniFile.toString());

        // Load ini file
        final Wini ini = new Wini(iniFile);

        // Create map of usernames to their permissions
        final ConcurrentMap<String, AppPermissions> permissionMap = new ConcurrentHashMap<String, AppPermissions>();

        // Create set of all known secrets
        final Set<String> knownSecrets = new HashSet<>();

        // Iterate over each section (each section is a secret)
        final Collection<Profile.Section> secretSections = ini.values();
        for (Profile.Section secretSection : secretSections) {

            // Update set of known secrets
            final String secretName = secretSection.getName();
            knownSecrets.add(secretName);

            // Each value in this section represents a user's permission to this secret
            for (final Entry<String, String> userPermission : secretSection.entrySet()) {
                final String username = userPermission.getKey();
                final String permissions = userPermission.getValue();

                // PRint username and secret
                //logger.info(username + "." + secretName + "\t\t = ");

                // Parse permissions
                final String[] permissionArray = permissions.split(",");
                //logger.info(Arrays.toString(permissionArray));

                // Add permissions from the comma-separated list
                permissionMap.putIfAbsent(username, new AppPermissions());
                final AppPermissions clientPermissions = permissionMap.get(username);
                for (final String permissionString : permissionArray) {
                    // Sanitize string and convert to enumeration
                    final Permissions permission = Permissions.valueOf(permissionString.trim().toUpperCase());
                    clientPermissions.addPermission(secretName, permission);
                }
            }
        }

        return new AccessEnforcement(permissionMap, knownSecrets);
    }

}