/**
 * All rights reserved -- Copyright 2015 Gluu Inc.
 */
package io.jans.ca.server.guice;

import com.google.inject.AbstractModule;
import com.google.inject.Singleton;
import io.jans.ca.server.RpServerConfiguration;
import io.jans.ca.server.op.OpClientFactory;
import io.jans.ca.server.op.OpClientFactoryImpl;
import io.jans.ca.server.persistence.service.PersistenceService;
import io.jans.ca.server.persistence.service.PersistenceServiceImpl;
import io.jans.ca.server.service.*;

/**
 * @author Yuriy Zabrovarnyy
 * @version 0.9, 22/11/2014
 */

public class GuiceModule extends AbstractModule {

    @Override
    protected void configure() {
        bind(RpServerConfiguration.class).toProvider(ConfigurationService.class);

        bind(ConfigurationService.class).in(Singleton.class);
        bind(PublicOpKeyService.class).in(Singleton.class);
        bind(RpService.class).in(Singleton.class);
        bind(HttpService.class).in(Singleton.class);
        bind(IntrospectionService.class).in(Singleton.class);
        bind(PersistenceService.class).to(PersistenceServiceImpl.class).in(Singleton.class);
        bind(MigrationService.class).in(Singleton.class);
        bind(DiscoveryService.class).in(Singleton.class);
        bind(ValidationService.class).in(Singleton.class);
        bind(StateService.class).in(Singleton.class);
        bind(RpSyncService.class).in(Singleton.class);
        bind(OpClientFactory.class).to(OpClientFactoryImpl.class).in(Singleton.class);
        bind(KeyGeneratorService.class).in(Singleton.class);
        bind(RequestObjectService.class).in(Singleton.class);
    }
}
