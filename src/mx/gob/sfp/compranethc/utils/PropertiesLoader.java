package mx.gob.sfp.compranethc.utils;

import java.util.Properties;

/**
 * Carga los archivos de propiedades de la aplicación.
 */
public final class PropertiesLoader {

	private static PropertiesLoader INSTANCE = new PropertiesLoader();

	private final static String PROPERTIES_CONFIG_PATH = "config-fp-signer.properties";

	private static Properties properties = null;

	private PropertiesLoader() {}

	public static PropertiesLoader getInstance() {
		return INSTANCE;
	}

	public String getProperty(String key) {
		String value = null;

		try {
			if (properties == null) {
				properties = loadProperties();
			}

			value = properties.getProperty(key);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return value;
	}

	private Properties loadProperties() throws Exception {
		Properties properties = new Properties();
		properties.load(this.getClass().getClassLoader().getResourceAsStream(PROPERTIES_CONFIG_PATH));
		return properties;
	}

}
