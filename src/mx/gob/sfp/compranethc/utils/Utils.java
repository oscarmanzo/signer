package mx.gob.sfp.compranethc.utils;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class Utils {

	private Utils(){}
	
	public static byte[] getFile(String path) throws IOException {
		byte[] buffer = null;
		FileInputStream fileInput = new FileInputStream (path);
		buffer = new byte[fileInput.available()];
		fileInput.read (buffer, 0x00, buffer.length);
		fileInput.close ();
		return buffer;
	}
	
	public static byte[] getBytes(InputStream datosEncInput) throws IOException {
        
	    if (datosEncInput==null) return new byte[0];
	        
	    BufferedOutputStream dest = null;
	    ByteArrayOutputStream bout = null;
	    int BUFFER_SIZE = 8192;
	    int count;
	    byte data[] = new byte[ BUFFER_SIZE ];
	    
	    bout = new ByteArrayOutputStream();
	    dest = new BufferedOutputStream( bout, BUFFER_SIZE );
	    
	    while( (count = datosEncInput.read( data, 0, BUFFER_SIZE ) ) != -1 ){
	        dest.write( data, 0, count );
	    }
	            
	    dest.flush();
	    dest.close();

	    return bout.toByteArray();
	}

	public static void saveFile(String path, byte[] data) throws IOException {
		FileOutputStream fcontent = new FileOutputStream(path);
		fcontent.write(data);
		fcontent.close();
	}
	
	public static int parseInt(String numero){
	    int valor = -1;

	    if (!esEntero(numero)) return valor;
	    
	    valor = Integer.parseInt(numero.trim());
	    return valor;
	}

	public static long parseLong(String numero){
	    long valor = -1;
	    
	    if (!esEntero(numero)) return valor;

	    valor = Long.parseLong(numero.trim());
	    return valor;
	}

	public static double parseDouble(String numero){
		double valor = -1;
	    
	    if (!esNumero(numero)) return valor;

	    valor = Double.parseDouble(numero.trim());
	    return valor;
	}

	public static boolean esEntero(String numero) {
		
		if (numero == null || numero.trim().isEmpty()) return false;

		Pattern pattern = Pattern.compile("^[0-9]+$");
		Matcher matcher = pattern.matcher(numero.trim());
		return matcher.find();
	}

	public static boolean esNumero(String numero) {

		if (numero == null || numero.trim().isEmpty()) return false;

		Pattern pattern = Pattern.compile("^\\-{0,1}([0-9]*|\\d*\\.\\d{1}?\\d*)$");
		Matcher matcher = pattern.matcher(numero.trim());
		return matcher.find();
	}

	public static long toLong(Object obj){
		if (obj==null) return 0;
		
		long result = 0;
		
		if (obj instanceof Long){
			result = (Long)obj;
		} else if (obj instanceof Integer){
			result = ((Integer)obj).longValue();
		} else if (obj instanceof BigDecimal){
			result = ((BigDecimal)obj).longValue();
		} else if (obj instanceof BigInteger){
			result = ((BigInteger)obj).longValue();
		} else if (obj instanceof Double){
			result = ((Double)obj).longValue();
		} else if (obj instanceof String){
			result = parseLong((String)obj);
		} else if (obj instanceof String){
			result = parseLong((String)obj);
		} else if (obj instanceof Number){
			result = ((Number)obj).longValue();
		}
		
		return result;
	}
	
	public static int toInt(Object obj){
		if (obj==null) return 0;
		
		int result = 0;
		
		if (obj instanceof Long){
			result = ((Long)obj).intValue();
		} else if (obj instanceof Integer){
			result = ((Integer)obj).intValue();
		} else if (obj instanceof BigDecimal){
			result = ((BigDecimal)obj).intValue();
		} else if (obj instanceof BigInteger){
			result = ((BigInteger)obj).intValue();
		} else if (obj instanceof Double){
			result = ((Double)obj).intValue();
		} else if (obj instanceof String){
			result = parseInt((String)obj);
		} else if (obj instanceof Number){
			result = ((Number)obj).intValue();
		}
		
		return result;
	}

	public static double toDouble(Object obj){
		if (obj==null) return 0;
		
		double result = 0;
		
		if (obj instanceof Long){
			result = ((Long)obj).doubleValue();
		} else if (obj instanceof Integer){
			result = ((Integer)obj).doubleValue();
		} else if (obj instanceof BigDecimal){
			result = ((BigDecimal)obj).doubleValue();
		} else if (obj instanceof BigInteger){
			result = ((BigInteger)obj).doubleValue();
		} else if (obj instanceof Double){
			result = ((Double)obj).doubleValue();
		} else if (obj instanceof String){
			result = parseDouble((String)obj);
		} else if (obj instanceof Number){
			result = ((Number)obj).doubleValue();
		}
		
		return result;
	}
	
	public static String toString(Object obj){
		if (obj==null) return null;
		
		String result = null;

		if (obj instanceof String){
			result = (String)obj;
		} else if (obj instanceof Long){
			result = ((Long)obj).toString();
		} else if (obj instanceof Integer){
			result = ((Integer)obj).toString();
		} else if (obj instanceof BigDecimal){
			result = ((BigDecimal)obj).toString();
		} else if (obj instanceof BigInteger){
			result = ((BigInteger)obj).toString();
		} else if (obj instanceof Double){
			result = ((Double)obj).toString();
		} else if (obj instanceof Number){
			result = ((Number)obj).toString();
		}
		
		return result;
	}
	
	public static Date toDate(Object obj){
		if (obj==null) return null;
		
		Date result = null;
		
		if (obj instanceof Date){
			result = (Date)obj;
		} else if (obj instanceof java.sql.Date){
			result = new Date(((java.sql.Date)obj).getTime());
		} else if (obj instanceof String){
			result = convert((String)obj);
		}
		
		return result;
	}
	
	public static Calendar toCalendar(Object obj){
		Calendar calendar = null;
		
		Date date = toDate(obj);
		
		if (date!=null){
			calendar = Calendar.getInstance();
			calendar.setTime(date);
		}

		return calendar;
	}

	public static Date convert(String cadenaFecha){
		
		if (cadenaFecha==null || cadenaFecha.isEmpty()) return null;
		
		SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy");
		try {
			return sdf.parse(cadenaFecha);
		} catch (ParseException e) {
			return null;
		}			
	
	}

}
