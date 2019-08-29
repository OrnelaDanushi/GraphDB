package neo4jDemo;
import org.neo4j.driver.v1.AuthTokens;
import org.neo4j.driver.v1.Driver;
import org.neo4j.driver.v1.GraphDatabase;
import org.neo4j.driver.v1.Record;
import org.neo4j.driver.v1.Session;
import org.neo4j.driver.v1.StatementResult;
import org.neo4j.driver.v1.Transaction; //remove the wrong driver in pom.xml
import org.neo4j.driver.v1.TransactionWork;
//import static org.neo4j.driver.v1.Values.parameters;

import java.util.Scanner;

public class Main {
	//Pay attention to what include in pom.xml

	static Driver driver = GraphDatabase.driver("bolt://127.0.0.1:7687", AuthTokens.basic("neo4j", "grafico2"));
	static String nomeFile = "ROUTING_FW_3ybouy";	
	static String HostCollection = "";

	public static void startDB(){
		//-----------------------------------------------------------------nascita nodi
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //delete the previous db
				public String execute( Transaction tx ){
					tx.run( "MATCH (n) DETACH DELETE n" );					
					System.out.println("Pulizia DB vecchio");
					return "";					
				}
			});			
		}
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //create nodes by .csv file 
				public String execute( Transaction tx ){
					tx.run( 
						"LOAD CSV WITH HEADERS FROM 'file:///"+nomeFile+".csv' AS row "		
						+"WITH row.Risk AS Risk, row.Host AS Host, row.Name AS Name, row.Description AS Description "
						+"MERGE (h:Host{ID:Host}) " 
						+"MERGE (r:Risk{ID:Risk}) "								
						+"MERGE (n:Name{ID:Name, Risk:Risk, Host:Host, Description:Description, ToConn:'' }) " 
						//+"RETURN h,r,n", parameters( "message", message ));
						//non posso ritornare il nodo se poi lo voglio stampare in stringa
						//+"RETURN DISTINCT h.ID AS HostNode, r.ID AS RiskNode, n.ID AS NameNode" 
						//ma anche così avrei sempre lo stesso output di righe create!
						//sol: conviene fare un'ulteriore query per sapere l'esito di tale costruzione
						);
					/*int contaHost=0, contaRisk=0, contaName=0;
					while ( result.hasNext() ){ 
						Record record = result.next();
						if( String.format( "%s", record.get( "HostNode" ).asString()).length() != 0 ){ contaHost++; }
						if( String.format( "%s", record.get( "RiskNode" ).asString()).length() != 0 ){ contaRisk++; }
						if( String.format( "%s", record.get( "NameNode" ).asString()).length() != 0 ){ contaName++; }
						//System.out.println( String.format( "%s", record.get( "RiskNode" ).asString()));
					}
					System.out.printf("AvvenutaCreazione:\n\t Host: %s\n\t Risk: %s\n\t Vulnerability: %s\n\n",contaHost,contaRisk,contaName); */
					System.out.println("Creazione DB nuovo");
					return "";					
				}
			});			
		}		
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //find the redundant relationships for the common vulnerabilities
				public String execute( Transaction tx ){
					tx.run( 
						"MATCH (nA:Name), (nB:Name) "
						+"WHERE nA.Risk=nB.Risk AND nA.Description=nB.Description AND "
						+"nA.ID=nB.ID AND nA.Host<>nB.Host AND nB.Host<>'' "
						+"SET nA.Host = nA.Host +'_'+ nB.Host , nB.Host='' "
						//+"RETURN nA,nB"
						);										
					System.out.println("Raccolta nodi insignificanti per filtraggio");
					return "";					
				}
			});										
		}				
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //delete nodes not necessary
				public String execute( Transaction tx ){
					tx.run( 
						"MATCH (n:Name{Risk:'None'}) "
						+"MATCH (r:Risk{ID:'None'}) "						
						+"MATCH (n1:Name{Host:''}) " //+"MATCH (h:Host{ID:'Host'}) "+ //is wrong!!!!!!!
						+"DELETE n,r,n1");										
					System.out.println("Cancellazione nodi insignificanti per filtraggio");
					return "";					
				}
			});	
		}			
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //read previous output 
				public String execute( Transaction tx ){
					StatementResult result = tx.run( 
							"MATCH (h:Host),(r:Risk),(n:Name) "
							+"RETURN count(DISTINCT h.ID), count(DISTINCT r.ID), count(DISTINCT n.ID) "
							);
					System.out.println("Output:");
					while ( result.hasNext() ){ 
						Record record = result.next();
						System.out.println("\tHost: " +record.get(0) );
						System.out.println("\tRisk: " +record.get(1) );
						System.out.println("\tVulnerability: " +record.get(2) );
					}
					return "";					
				}
			});			
		}
	}	
	
	public static void edges(){
		//-----------------------------------------------------------------nascita archi					
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //hosts+vulnerabilities(also common)+risk				
				public String execute( Transaction tx ){
					//StatementResult result = 
					tx.run( 
						"MATCH (n:Name),(r:Risk),(h:Host) "
						+"WHERE n.Risk=r.ID AND n.Host CONTAINS h.ID "						
						+"MERGE (h)-[:HAS_VULN]-(n) "		
						+"MERGE (n)-[:HAS_RISK]-(r) " 
						+"RETURN h.ID,n.ID,r.ID"
						);										
					System.out.println("\nCreazione archi: Host->Vulnerability->Risk");
					/*while ( result.hasNext() ){ 
						Record record = result.next();
						System.out.println("\t"+record.get(0)+"\t"+record.get(1)+"\t"+record.get(2) );
					}*/
					HostCollection = "";
					return "";					
				}
			});				
		}		
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //count of vulnerabilities per host
				public String execute( Transaction tx ){
					StatementResult result = tx.run( 
						"MATCH (h:Host)-[r:HAS_VULN]->(n:Name) "
						+ "RETURN h.ID, count(r) AS connections "
						+ "ORDER BY connections DESC "
						);
					System.out.println("Conteggio vulnerabilità per ciascun Host");
					while ( result.hasNext() ){ 
						Record record = result.next();
						System.out.println("\t"+record.get(0)+"\t"+record.get(1) );		
						HostCollection = HostCollection + record.get(0) + "_" ;
						
					}
					return "";					
				}
			});	
		}
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //creating physicalConnections between hosts, with an edge
				public String execute( Transaction tx ){
					StatementResult result = tx.run( 
						"LOAD CSV WITH HEADERS FROM 'file:///ConnessioniFisicheHosts.csv' AS row "
						+"WITH row.NodoA AS nodoA, row.NodoB AS nodoB "						
						+"MATCH (nA:Host),(nB:Host) " 
						+"WHERE nA.ID=nodoA AND nB.ID=nodoB AND nodoA<>nodoB "
						+"MERGE (nA) -[:PHYSIC]-> (nB) "
						+"RETURN nA.ID,nB.ID"
						);										
					System.out.println("Creazione connessioni fisiche tra i seguenti host:");
					while ( result.hasNext() ){ 
						Record record = result.next();
						System.out.println("\t"+record.get(0)+"\t->\t"+record.get(1) );
					}
					return "";					
				}
			});	
		}				
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //creating logicalConnections between hosts, with an intermediate node
				public String execute( Transaction tx ){
					StatementResult result = tx.run( 
						"LOAD CSV WITH HEADERS FROM 'file:///ConnessioniLogicheHosts.csv' AS row "
						+"WITH row.NodoA AS nodoA, row.NodoB AS nodoB "						
						+"MATCH (nA:Host),(nB:Host) " 
						+"WHERE nA.ID=nodoA AND nB.ID=nodoB AND nodoA<>nodoB "
						+"MERGE (c:CONN{ID:nA.ID+'->'+nB.ID}) "
						+"MERGE (nA)-[:LOGIC]->(c) "
						+"MERGE (c)-[:LOGIC]->(nB) "
						+"RETURN nA.ID,nB.ID "
						);										
					System.out.println("Creazione connessioni logiche tra i seguenti host:");
					while ( result.hasNext() ){ 
						Record record = result.next();
						System.out.println("\t"+record.get(0)+"\t->\t"+record.get(1) );
					}
					return "";					
				}
			});	
		}		
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //creating vulnerabilityConnections
				public String execute( Transaction tx ){
					tx.run( 
						"MATCH (c:CONN),(hB:Host),(n:Name), path = ((c)-[:LOGIC*]->(hB)) "
						+"WHERE (hB)-[:HAS_VULN*]->(n) "						
						+"MERGE r1=((c)-[:VULN]->(n)) " 
						+"MERGE r2=((n)-[:VULN]->(hB)) "
						+"SET (CASE WHEN not(n.ToConn CONTAINS c.ID) then n END).ToConn=n.ToConn+c.ID "
						//+"RETURN path,r1,r2 "
						//+"ORDER BY LENGTH(path) DESC "
						);										
					System.out.println("Creazione connessioni per le vulnerabilità");
					return "";					
				}
			});	
		}				
	}	

	public static void updating(){
		//----------------------------------------------------------------aggiornamento connessioni logiche							
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //before the logicalConnections counting
				public String execute( Transaction tx ){
					tx.run( 
						"MATCH (c:CONN) "
						+"SET c.connected=0 "						
						//+"RETURN c "
						);										
					System.out.println("\nPrima dell'aggiornamento delle connessioni logiche");
					return "";					
				}
			});	
		}//after this execution change manually the logicalConnections file				
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //during the logicalConnections counting
				public String execute( Transaction tx ){
					StatementResult result = tx.run( 
						"MATCH (c:CONN) "
						+"LOAD CSV WITH HEADERS FROM 'file:///ConnessioniLogicheHosts.csv' AS row "
						+"WITH row.NodoA AS nodoA, row.NodoB AS nodoB, split(c.ID,'->') AS hostNames, c "
						+"MATCH (nA:Host),(nB:Host) "
						+"WHERE nA.ID=nodoA AND nB.ID=nodoB AND nodoA<>nodoB "
						+"SET (CASE WHEN (nA.ID=hostNames[0] AND nB.ID=hostNames[1]) then c END).connected=1 "
						+"RETURN DISTINCT nA.ID,nB.ID" //sono quelle tutt'ora presenti
						);
					System.out.println("Durante l'aggiornamento delle connessioni logiche");
					while ( result.hasNext() ){ 
						Record record = result.next();
						System.out.println("\t"+record.get(0)+"\t->\t"+record.get(1) );
					}
					return "";					
				}
			});	
		}		
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //deleting the logicalConnections for the updating, the latest edges
				public String execute( Transaction tx ){
					tx.run( 
						"MATCH (c:CONN{connected:0}), (n:Name)-[v:VULN]->(hB:Host) "
						+"WHERE n.ToConn CONTAINS c.ID "
						+"WITH replace(n.ToConn,c.ID,'') as cleaned,n,v "
						+"SET n.ToConn=cleaned "
						+"DELETE CASE WHEN cleaned='' THEN v END "
						);
					System.out.println("Cancellazione archi lontani dal nodo fittizio per aggiornamento connessioni logiche");
					return "";					
				}
			});	
		}		
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //deleting the remaining part of the logicConnections
				public String execute( Transaction tx ){
					tx.run( 
						"MATCH (c:CONN{connected:0}) "
						+"DETACH DELETE c "
						);
					System.out.println("Cancellazione nodo fittizio per aggiornamento connessioni logiche");
					return "";					
				}
			});	
		}
	}

	public static void querying( final String hostA, final String hostB, final String noHost ){
		//---------------------------------------------------------------------------------------								
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //returning all the connections
				public String execute( Transaction tx ){
					//StatementResult result = 
					tx.run( 
						"MATCH p=(n)-[r:LOGIC|:PHYSIC|:VULN]->(m) "
						+"RETURN n.ID,type(r),m.ID "
						);
					System.out.println("\nLettura tipologie connessioni");
					/*while ( result.hasNext() ){ 
						Record record = result.next();
						System.out.println("\t"+record.get(0)+"\t-"+record.get(1)+"\t->"+record.get(2) );
					}*/
					return "";					
				}
			});	
		}
		
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //returning all the paths between 2 nodes
				public String execute( Transaction tx ){
					StatementResult result = tx.run( 
						"MATCH paths=((nA:Host)-[r:PHYSIC|:LOGIC|:VULN*1..4]->(nB:Host)) "
						+ "WHERE nA.ID="+hostA+ " AND nB.ID="+hostB
						+"RETURN paths"
						);
					/*System.out.println("Lettura tutti i possibili cammini tra 2 Host specifici: "+hostA+" ->* "+hostB);
					while ( result.hasNext() ){ 
						Record record = result.next();
						System.out.println("\t"+record.get(0) );
											
					}*/
					return "";					
				}
			});	
		}
		
		try ( Session session = driver.session() ){
			session.writeTransaction( new TransactionWork<String>(){ //returning the paths between 2 nodes which not go through a specific node
				public String execute( Transaction tx ){
					StatementResult result = tx.run( 
						"MATCH paths=((nA:Host)-[:PHYSIC|:LOGIC|:VULN*1..4]->(nB:Host)) "
						+"WHERE ALL ( r in nodes(paths) WHERE r.ID<>'"+noHost+"') "
								+ "AND nA.ID="+hostA+ " AND nB.ID="+hostB 
						+"RETURN paths "
						);
					System.out.println("Lettura tutti i possibili cammini tra 2 Host specifici: "+hostA+" ->* "+hostB+" non passando da: "+noHost);
					while ( result.hasNext() ){ 
						Record record = result.next();
						System.out.println("\t"+record.get(0) );							
					}
					return "";					
				}
			});	
		}					
	}
	
	public static void main( String[] args ){				
		
		Boolean continua=true;
		Scanner sc = new Scanner(System.in);
		
		while( continua ){
			System.out.println("Scegli operazione");
			int scelta = sc.nextInt();
			switch( scelta ){
				case 0 : 
					System.out.println("Scegli File diverso da quello di default");
					System.out.println("\ta : ROUTING_FW_3ybouy");
					System.out.println("\tb : INT_PXE_wwih7h");
					System.out.println("\tc : HVAC_zj041u");
					System.out.println("\td : HVAC_PLC_gii4vv");
					System.out.println("\te : DRONE_jpae2j");
					System.out.println("\tf : DMZ_dddl1g");
					System.out.println("\tg : LAB_koaa71");					
					System.out.println("\th : INT_9u5sz7");
					
					
					String nome = sc.next(); //nextLine() crea problemi
					switch( nome ){
						case "a" : nomeFile = "ROUTING_FW_3ybouy";	break;
						case "b" : nomeFile = "INT_PXE_wwih7h";		break;
						case "c" : nomeFile = "HVAC_zj041u";		break;
						case "d" : nomeFile = "HVAC_PLC_gii4vv";	break;
						case "e" : nomeFile = "DRONE_jpae2j";		break;
						case "f" : nomeFile = "DMZ_dddl1g";			break;
						case "g" : nomeFile = "LAB_koaa71";			break;
						case "h" : nomeFile = "INT_9u5sz7";			break;

						default : nomeFile = "ROUTING_FW_3ybouy";
					}		
					if( nome.length() != 0 ){ startDB(); 	}				
					break;
				case 1 : edges(); break; 
				case 2 : updating(); break;
				case 3 : 
					System.out.println("Per poter visualizzare anche la query dei possibili cammini tra 2 host specifici\n"
							+"assicurarsi di aver prima fatto il passaggio 1.\n"
							+ "E' possibile scegliere tra i seguenti host: (hostA, hostB, noHost)\n"
							+ "altrimenti cliccare numero negativo per la non scelta");
					//System.out.println(HostCollection);
					String[] arrHostCollection = HostCollection.split("_");
					for( int i=0; i<arrHostCollection.length; i++){
						System.out.println(i+": "+arrHostCollection[i]);
					}
					int hostA=sc.nextInt(); if( hostA<0 ){ hostA=0; arrHostCollection[hostA]=""; }
					int hostB=sc.nextInt();  if( hostB<0 ){ hostB=0; arrHostCollection[hostB]=""; }
					int noHost=sc.nextInt(); if( noHost<0 ){ noHost=0; arrHostCollection[noHost]=""; }					
					querying(arrHostCollection[hostA], arrHostCollection[hostB], arrHostCollection[noHost] );
					
					//System.out.println(arrHostCollection[hostA] + arrHostCollection[hostB] + arrHostCollection[noHost] );
					break; 
				case 4 : continua = false; break; 
				default: scelta = sc.nextInt();
			}			
		}
		
		sc.close();
		driver.close(); 				
	}
}
