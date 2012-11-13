package net.grinder.util;

import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class NetworkUtilTest {
	@Test
	public void testLocalHostName() {
		String localHostAddress = NetworkUtil.getLocalHostAddress();
		assertThat(localHostAddress, notNullValue());
		assertThat(localHostAddress, not("127.0.0.1"));
		localHostAddress = NetworkUtil.getLocalHostAddress();
		assertThat(localHostAddress, notNullValue());
		assertThat(localHostAddress, not("127.0.0.1"));
	}
}
