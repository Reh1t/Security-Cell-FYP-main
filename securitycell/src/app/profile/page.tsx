'use client'
import CardRotation from "@/components/CardRotation";
import Footer from "@/components/Footer";
import HeaderHome from "@/components/HeaderHome";
import React, { useEffect, useState } from "react";

function Profile() {

  const websitePrefix = 'www.securitycell.themavennest.shop';



  const image = localStorage.getItem(`${websitePrefix}-user-firstName`);


  const [userData, setUserData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [domainName, setDomainName] = useState("");


  const userId = localStorage.getItem(`${websitePrefix}-user-userID`);
  console.log(userId);

  const fetchUserProfile = async () => {
    try {
      const response = await fetch(
        'https://securitycell.themavennest.shop/securitycell/database/profile.php',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ user_id: userId }),
        }
      );

      if (!response.ok) {
        throw new Error("Failed to fetch user profile");
      }

      const data = await response.json();
      if (data.success) {
        setUserData(data.user);
        setDomainName(data.user.verified_domains[0].domain);
        console.log(data.user.verified_domains[0].domain);
        console.log(data.user);
      } else {
        setError(data.message);
      }
    } catch (err) {
      setError("An unexpected error occurred");
    } finally {
      setLoading(false);
    }
  };

  async function fetchDomainDetails(domainName) {
    try {
      const response = await fetch(
        `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_XwOuruwpLhoxBcFRwz9b8DJXaDnRX&domainName=${domainName}`
      );
  
      if (!response.ok) {
        throw new Error("Failed to fetch domain details");
      }
  
      const xmlData = await response.text();
  
      // Parse the XML response
      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(xmlData, "text/xml");
  
      // Extract necessary details from registryData
      const registrarName =
        xmlDoc.getElementsByTagName("registrarName")[0]?.textContent || "N/A";
      const createdDate =
        xmlDoc
          .getElementsByTagName("registryData")[0]
          ?.getElementsByTagName("createdDate")[0]?.textContent || "N/A";
      const expiresDate =
        xmlDoc
          .getElementsByTagName("registryData")[0]
          ?.getElementsByTagName("expiresDate")[0]?.textContent || "N/A";
  
      return {
        registrarName,
        createdDate,
        expiresDate,
      };
    } catch (error) {
      console.error("Error fetching domain details:", error);
      return {
       
      };
    }
  }
  
  

  const [domainDetails, setDomainDetails] = useState({
    registrarName: "",
    createdDate: "",
    expiresDate: "",
  });

  useEffect(() => {
   
  }, []);

  useEffect(() => {
    console.log("domain name: "+domainName);
    async function getDetails() {
      const details = await fetchDomainDetails(domainName);
      setDomainDetails(details);
      fetchUserProfile();
    }
    getDetails();
  }, [domainName]);





  // if (loading) return <p>Loading...</p>;
  // if (error) return <p className="text-red-500">{error}</p>;





  return (
    
<div className="block bg-white min-h-screen">
 
 <HeaderHome />

 {userData && (
 <div className="min-h-screen px-20">
 <div className="flex flex-row rounded-lg border border-gray-200/80 bg-white p-6 shadow-lg h-60">
    <div className="relative">
      {/* <img className="w-40 h-40 rounded-md object-cover" src="https://api.lorem.space/image/face?w=150&h=150"
        alt="User" /> */}
        {/* <div style={{ width: '10rem', height: '10rem', display: 'flex', objectFit: 'cover', alignItems: 'center', justifyContent: 'center', fontSize: '1rem', color: 'white' }}>
                      {image ? image.charAt(0).toUpperCase() : ''}
                    </div> */}

                    <div className="rounded-full bg-black shadow w-16 h-16 flex items-center justify-center relative ml-4 text-white">
                    {/* Add your avatar image or icon here */}
                    <div style={{ width: '100%', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1rem', color: 'white' }}>
                      {image ? image.charAt(0).toUpperCase() : ''}
                    </div>
                  </div>

      <div
        className="absolute -right-3 bottom-5 h-5 w-5 sm:top-2 rounded-full border-4 border-white bg-green-400 sm:invisible md:visible"
        title="User is online"></div>
    </div>

    <div className="flex flex-col px-6">
      <div className="flex h-8 flex-row">
        <a href="https://github.com/EgoistDeveloper/" target="_blank">
          <h2 className="text-lg font-semibold text-gray-900">{userData.name}</h2>
        </a>

        <svg className="my-auto ml-2 h-5 fill-blue-400" xmlns="http://www.w3.org/2000/svg"
           version="1.1" width="24" height="24" viewBox="0 0 24 24">
          <path
            d="M23,12L20.56,9.22L20.9,5.54L17.29,4.72L15.4,1.54L12,3L8.6,1.54L6.71,4.72L3.1,5.53L3.44,9.21L1,12L3.44,14.78L3.1,18.47L6.71,19.29L8.6,22.47L12,21L15.4,22.46L17.29,19.28L20.9,18.46L20.56,14.78L23,12M10,17L6,13L7.41,11.59L10,14.17L16.59,7.58L18,9L10,17Z" />
          </svg>
      </div>

      <div className="my-2 flex flex-row space-x-2">
        <div className="flex flex-row">
          <svg className="mr-2 h-4 w-4 fill-gray-500/80" xmlns="http://www.w3.org/2000/svg"
             version="1.1" width="24" height="24" viewBox="0 0 24 24">
            <path
              d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M7.07,18.28C7.5,17.38 10.12,16.5 12,16.5C13.88,16.5 16.5,17.38 16.93,18.28C15.57,19.36 13.86,20 12,20C10.14,20 8.43,19.36 7.07,18.28M18.36,16.83C16.93,15.09 13.46,14.5 12,14.5C10.54,14.5 7.07,15.09 5.64,16.83C4.62,15.5 4,13.82 4,12C4,7.59 7.59,4 12,4C16.41,4 20,7.59 20,12C20,13.82 19.38,15.5 18.36,16.83M12,6C10.06,6 8.5,7.56 8.5,9.5C8.5,11.44 10.06,13 12,13C13.94,13 15.5,11.44 15.5,9.5C15.5,7.56 13.94,6 12,6M12,11A1.5,1.5 0 0,1 10.5,9.5A1.5,1.5 0 0,1 12,8A1.5,1.5 0 0,1 13.5,9.5A1.5,1.5 0 0,1 12,11Z" />
            </svg>

          <div className="text-xs text-gray-400/80 hover:text-gray-400">{userData.verified === 1 ? "Account Verified" : "Account not Verified"}</div>
        </div>

        {/* <div className="flex flex-row">
          <svg className="mr-2 h-4 w-4 fill-gray-500/80" xmlns="http://www.w3.org/2000/svg"
             version="1.1" width="24" height="24" viewBox="0 0 24 24">
            <path
              d="M12,6.5A2.5,2.5 0 0,1 14.5,9A2.5,2.5 0 0,1 12,11.5A2.5,2.5 0 0,1 9.5,9A2.5,2.5 0 0,1 12,6.5M12,2A7,7 0 0,1 19,9C19,14.25 12,22 12,22C12,22 5,14.25 5,9A7,7 0 0,1 12,2M12,4A5,5 0 0,0 7,9C7,10 7,12 12,18.71C17,12 17,10 17,9A5,5 0 0,0 12,4Z" />
            </svg>

          <div className="text-xs text-gray-400/80 hover:text-gray-400"></div>
        </div> */}

        <div className="flex flex-row">
          <svg className="mr-2 h-4 w-4 fill-gray-500/80" xmlns="http://www.w3.org/2000/svg"
            version="1.1" width="24" height="24" viewBox="0 0 24 24">
            <path
              d="M12,15C12.81,15 13.5,14.7 14.11,14.11C14.7,13.5 15,12.81 15,12C15,11.19 14.7,10.5 14.11,9.89C13.5,9.3 12.81,9 12,9C11.19,9 10.5,9.3 9.89,9.89C9.3,10.5 9,11.19 9,12C9,12.81 9.3,13.5 9.89,14.11C10.5,14.7 11.19,15 12,15M12,2C14.75,2 17.1,3 19.05,4.95C21,6.9 22,9.25 22,12V13.45C22,14.45 21.65,15.3 21,16C20.3,16.67 19.5,17 18.5,17C17.3,17 16.31,16.5 15.56,15.5C14.56,16.5 13.38,17 12,17C10.63,17 9.45,16.5 8.46,15.54C7.5,14.55 7,13.38 7,12C7,10.63 7.5,9.45 8.46,8.46C9.45,7.5 10.63,7 12,7C13.38,7 14.55,7.5 15.54,8.46C16.5,9.45 17,10.63 17,12V13.45C17,13.86 17.16,14.22 17.46,14.53C17.76,14.84 18.11,15 18.5,15C18.92,15 19.27,14.84 19.57,14.53C19.87,14.22 20,13.86 20,13.45V12C20,9.81 19.23,7.93 17.65,6.35C16.07,4.77 14.19,4 12,4C9.81,4 7.93,4.77 6.35,6.35C4.77,7.93 4,9.81 4,12C4,14.19 4.77,16.07 6.35,17.65C7.93,19.23 9.81,20 12,20H17V22H12C9.25,22 6.9,21 4.95,19.05C3,17.1 2,14.75 2,12C2,9.25 3,6.9 4.95,4.95C6.9,3 9.25,2 12,2Z" />
            </svg>

          <div className="text-xs text-gray-400/80 hover:text-gray-400">{userData.email}</div>
        </div>
      </div>

      <div className="mt-2 flex flex-row items-center space-x-5">
        <a href="#"
          className="flex h-20 w-40 flex-col items-center justify-center rounded-md border border-dashed border-gray-200 transition-colors duration-100 ease-in-out hover:border-gray-400/80">
          <div className="flex flex-row items-center justify-center">
            <svg className="mr-3 fill-gray-500/95" xmlns="http://www.w3.org/2000/svg"
               version="1.1" width="24" height="24" viewBox="0 0 24 24">
              <path
                d="M12,23A1,1 0 0,1 11,22V19H7A2,2 0 0,1 5,17V7A2,2 0 0,1 7,5H21A2,2 0 0,1 23,7V17A2,2 0 0,1 21,19H16.9L13.2,22.71C13,22.89 12.76,23 12.5,23H12M13,17V20.08L16.08,17H21V7H7V17H13M3,15H1V3A2,2 0 0,1 3,1H19V3H3V15M9,9H19V11H9V9M9,13H17V15H9V13Z" />
              </svg>

            <span className="font-bold text-gray-600"> Not Available </span>
          </div>

          <div className="mt-2 text-sm text-gray-400">Technical Support</div>
        </a>

        <a href="#"
          className="flex h-20 w-40 flex-col items-center justify-center rounded-md border border-dashed border-gray-200 transition-colors duration-100 ease-in-out hover:border-gray-400/80">
          <div className="flex flex-row items-center justify-center">
            <svg className="mr-3 fill-gray-500/95" xmlns="http://www.w3.org/2000/svg"
               version="1.1" width="24" height="24" viewBox="0 0 24 24">
              <path
                d="M2.5 19.6L3.8 20.2V11.2L1.4 17C1 18.1 1.5 19.2 2.5 19.6M15.2 4.8L20.2 16.8L12.9 19.8L7.9 7.9V7.8L15.2 4.8M15.3 2.8C15 2.8 14.8 2.8 14.5 2.9L7.1 6C6.4 6.3 5.9 7 5.9 7.8C5.9 8 5.9 8.3 6 8.6L11 20.5C11.3 21.3 12 21.7 12.8 21.7C13.1 21.7 13.3 21.7 13.6 21.6L21 18.5C22 18.1 22.5 16.9 22.1 15.9L17.1 4C16.8 3.2 16 2.8 15.3 2.8M10.5 9.9C9.9 9.9 9.5 9.5 9.5 8.9S9.9 7.9 10.5 7.9C11.1 7.9 11.5 8.4 11.5 8.9S11.1 9.9 10.5 9.9M5.9 19.8C5.9 20.9 6.8 21.8 7.9 21.8H9.3L5.9 13.5V19.8Z" />
              </svg>

            <span className="font-bold text-gray-600"> BASIC </span>
          </div>

          <div className="mt-2 text-sm text-gray-400">Subscription Plan</div>
        </a>

        <a href="#"
          className="flex h-20 w-40 flex-col items-center justify-center rounded-md border border-dashed border-gray-200 transition-colors duration-100 ease-in-out hover:border-gray-400/80">
          <div className="flex flex-row items-center justify-center">
            <svg className="mr-3 fill-gray-500/95" xmlns="http://www.w3.org/2000/svg"
               version="1.1" width="24" height="24" viewBox="0 0 24 24">
              <path
                d="M5.68,19.74C7.16,20.95 9,21.75 11,21.95V19.93C9.54,19.75 8.21,19.17 7.1,18.31M13,19.93V21.95C15,21.75 16.84,20.95 18.32,19.74L16.89,18.31C15.79,19.17 14.46,19.75 13,19.93M18.31,16.9L19.74,18.33C20.95,16.85 21.75,15 21.95,13H19.93C19.75,14.46 19.17,15.79 18.31,16.9M15,12A3,3 0 0,0 12,9A3,3 0 0,0 9,12A3,3 0 0,0 12,15A3,3 0 0,0 15,12M4.07,13H2.05C2.25,15 3.05,16.84 4.26,18.32L5.69,16.89C4.83,15.79 4.25,14.46 4.07,13M5.69,7.1L4.26,5.68C3.05,7.16 2.25,9 2.05,11H4.07C4.25,9.54 4.83,8.21 5.69,7.1M19.93,11H21.95C21.75,9 20.95,7.16 19.74,5.68L18.31,7.1C19.17,8.21 19.75,9.54 19.93,11M18.32,4.26C16.84,3.05 15,2.25 13,2.05V4.07C14.46,4.25 15.79,4.83 16.9,5.69M11,4.07V2.05C9,2.25 7.16,3.05 5.68,4.26L7.1,5.69C8.21,4.83 9.54,4.25 11,4.07Z" />
              </svg>

            <span className="font-bold text-gray-600"> {userData.verified_domains?.length || 0} </span>
          </div>

          <div className="mt-2 text-sm text-gray-400">Domains</div>
        </a>
      </div>
    </div>

    <div className="w-100 flex flex-grow flex-col items-end justify-start">
      <div className="flex flex-row space-x-3">
        <button
        onClick={() => window.location.href="/domain-verification"}
          className="flex rounded-md bg-blue-500 py-2 px-4 text-white transition-all duration-150 ease-in-out hover:bg-blue-600">
          <svg className="mr-2 fill-current" xmlns="http://www.w3.org/2000/svg" 
            version="1.1" width="24" height="24" viewBox="0 0 24 24">
            <path d="M19,13H13V19H11V13H5V11H11V5H13V11H19V13Z" /></svg>

          Domain
        </button>

        <button className="flex rounded-md bg-gray-100 py-2 px-1 text-white 
        transition-all duration-150 ease-in-out hover:bg-gray-200">
          <svg className="fill-gray-500" xmlns="http://www.w3.org/2000/svg" 
            version="1.1" width="24" height="24" viewBox="0 0 24 24">
            <path
              d="M12,16A2,2 0 0,1 14,18A2,2 0 0,1 12,20A2,2 0 0,1 10,18A2,2 0 0,1 12,16M12,10A2,2 0 0,1 14,12A2,2 0 0,1 12,14A2,2 0 0,1 10,12A2,2 0 0,1 12,10M12,4A2,2 0 0,1 14,6A2,2 0 0,1 12,8A2,2 0 0,1 10,6A2,2 0 0,1 12,4Z" />
            </svg>
        </button>
      </div>
    </div>
  </div>

  <CardRotation />

  <div className="bg-white dark:bg-gray-900">
            <div className="container px-6 py-8 mb-16">
                <p className="text-md text-center text-gray-500 dark:text-gray-300">
                    Keep your domains verified
                </p>

                <h1 className="mt-4 text-3xl font-semibold text-center text-gray-800 capitalize lg:text-4xl dark:text-white mb-8">Domains Owned</h1>
            
                
                {userData.verified_domains.map((domain, index) => (
    <div
      key={index}
      className={`mb-6 flex items-center justify-between py-6 px-8 mx-auto border cursor-pointer rounded-xl ${
        domain.status === 1 ? "border-blue-500" : "dark:border-gray-700"
      }`}
    >
      <div className="flex items-center">
        <svg
          xmlns="http://www.w3.org/2000/svg"
          className={`w-5 h-5 sm:h-9 sm:w-9 ${
            domain.status === 1 ? "text-blue-600" : "text-gray-400"
          }`}
          viewBox="0 0 20 20"
          fill="currentColor"
        >
          <path
            fillRule="evenodd"
            d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
            clipRule="evenodd"
          />
        </svg>

        <div className="flex flex-col items-start mx-5 space-y-2">
          <h2
            className={`text-lg text-gray-700 font-medium sm:text-2xl ${
              domain.status === 1 ? "text-gray-700" : "dark:text-gray-200"
            }`}
          >
            {domain.domain}
          </h2>
          <div
            className={`px-2 text-xs sm:px-4 sm:py-1 rounded-full bg-gray-100 dark:bg-gray-700 ${
              domain.status === 1 ? "text-blue-500" : "text-gray-500"
            }`}
          >
            {domain.verified_at}
          </div>
        </div>
      </div>


  {domain.status === 1 ? (
    <h2
    className={`text-sm font-semibold sm:text-xl ${
      domain.status === 1 ? "text-gray-500" : "text-gray-500 dark:text-gray-300"
    }`}
  >
    <div className="flex flex-col items-end">
    {domainDetails.registrarName}
    
    <p className="text-xs text-gray-400 mt-2">{domainDetails.createdDate}</p>
    <p className="text-xs text-gray-400">{domainDetails.expiresDate}</p>

    </div>
  </h2>
  ) : (
    <div className="flex justify-center">
    <button onClick={() => window.location.href="/domain-verification"} className="px-8 py-2 tracking-wide text-white capitalize transition-colors duration-200 transform bg-blue-600 rounded-md hover:bg-blue-500 focus:outline-none focus:bg-blue-500 focus:ring focus:ring-blue-300 focus:ring-opacity-80">
        Verify
    </button>
</div>
  )}
      
    </div>
  ))}

                
            </div>
        </div>

 </div>

        )}

  


  <Footer />
</div>
   
  );
}

export default Profile;