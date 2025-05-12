package com.lzk.config;

/**
 * @author Desmondlzk
 * Date: 2025/4/5$
 */

import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JPBCConfig {

    @Bean
    public Pairing pairing() {
        return PairingFactory.getPairing("a.properties");
    }
}

