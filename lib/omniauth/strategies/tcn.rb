require 'omniauth-oauth2'
require 'builder'
require 'nokogiri'
require 'rest_client'

module OmniAuth
  module Strategies
    class Tcn < OmniAuth::Strategies::OAuth2
      option :name, 'tcn'

      option :client_options, {
        authorize_url: 'http://member.thechurchnetwork.com/Online/ssologin.aspx',
        site: 'http://devrise.nacba.net',
        soap_poin: '/NACBAweb_service/nacbaweb_service.asmx',
        authentication_token: 'MUST BE SET'
      }

      uid { info[:IMISID] }

      info do
        raw_user_info
      end

      extra do
        { :raw_info => get_user_info }
      end

      def creds
        self.access_token
      end

      def request_phase
        slug = session['omniauth.params']['origin'].gsub(/\//,"")

        auth_request = authorize(callback_url, slug)
        redirect auth_request["data"]["authUrl"]
      end

      def request_phase
        slug = session['omniauth.params']['origin'].gsub(/\//,"")
        redirect authorize_url + "&redirectURL=" + callback_url + "?slug=#{slug}"
      end

      def callback_phase
        self.access_token = {
          :token => customer_token
        }

        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + request.params['slug']
        call_app!
      end

      def auth_hash
        hash = AuthHash.new(:provider => name, :uid => uid)
        hash.info = info
        hash.credentials = creds
        hash
      end

      def raw_user_info
        @doc ||= Nokogiri::XML(get_user_info)
        @doc.remove_namespaces!
        @raw_user_info ||= {
          first_name: @doc.xpath('//FirstName').text,
          last_name: @doc.xpath('//LastName').text,
          email: @doc.xpath('//Email').text,
          full_name: @doc.xpath('//FullName').text,
          IMISID: @doc.xpath('//IMISID').text
        }
      end

      def build_xml_getUserbyUserID iMISID, key
        xml_builder = ::Builder::XmlMarkup.new
        xml_builder.instruct! :xml, :version=>"1.0", :encoding=>"UTF-8"
        xml_builder.soap12 :Envelope, "xmlns:xsi"=>"http://www.w3.org/2001/XMLSchema-instance", "xmlns:xsd"=>"http://www.w3.org/2001/XMLSchema", "xmlns:soap12"=>"http://www.w3.org/2003/05/soap-envelope" do
          xml_builder.soap12 :Header do
            xml_builder.UserKey  xmlns: "http://NACBAweb_service.org/" do
              xml_builder.Key key
            end
          end
          xml_builder.soap12 :Body do
            xml_builder.getUserbyUserID xmlns: "http://NACBAweb_service.org/" do
              xml_builder.iMISID iMISID
            end
          end
        end
        xml_builder.target!
      end

      def get_user_info
        @response ||= RestClient.post( soap_poin_url, 
          build_xml_getUserbyUserID(session['omniauth.params']['memberID'], authentication_token),
          { "Content-Type" => "application/soap+xml; charset=utf-8" }
        )

        if @response.code == 200
          @response.body
        else
          raise "Bad response from server TCN"
        end
      end

      def soap_poin_url
        "#{options.client_options.site}#{options.client_options.soap_poin}"
      end

      private

      def authorize_url
        options.client_options.authorize_url
      end

      def authentication_token
        options.client_options.authentication_token
      end
    end
  end
end
