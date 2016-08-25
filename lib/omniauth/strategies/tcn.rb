require 'omniauth-oauth2'
require 'builder'
require 'nokogiri'
require 'rest_client'

module OmniAuth
  module Strategies
    class Tcn < OmniAuth::Strategies::OAuth2
      option :name, 'tcn'

      option :client_options, {
        authorize_url: 'MUST BE SET',
        site: 'MUST BE SET',
        soap_poin: '/NACBAweb_service/nacbaweb_service.asmx',
        authentication_token: 'MUST BE SET'
      }

      uid { info[:IMISID] }

      info do
        raw_user_info
      end

      extra do
        { :raw_info => raw_user_info }
      end

      def request_phase
        slug = session['omniauth.params']['origin'].gsub(/\//,"")
        redirect authorize_url + "?returnURL=" + callback_url + "?slug=#{slug}"
      end

      def callback_phase
        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + request.params['slug']
        call_app!
      end

      def credentials
        {
          soap_poin_url: soap_poin_url,
          authentication_token: authentication_token
        }
      end

      def auth_hash
        hash = AuthHash.new(:provider => name, :uid => uid)
        hash.info = info
        hash.credentials = credentials
        hash
      end

      def member_type
        @member_type ||= raw_assigned_roles.split(",").first
      end

      def raw_assigned_roles
        @doc_assigned_roles ||= Nokogiri::XML(get_assigned_roles)
        @doc_assigned_roles.remove_namespaces!
        @doc_assigned_roles.xpath('//assignedRolesResult').text
      end

      def raw_user_info
        @doc ||= Nokogiri::XML(get_user_info)
        @doc.remove_namespaces!
        @raw_user_info ||= {
          first_name: @doc.xpath('//FirstName').text,
          last_name: @doc.xpath('//LastName').text,
          email: @doc.xpath('//Email').text,
          full_name: @doc.xpath('//FullName').text,
          IMISID: @doc.xpath('//IMISID').text,
          username: @doc.xpath('//IMISID').text,
          member_type: member_type
        }
      end

      def get_assigned_roles
        @roles_response ||= RestClient.post( soap_poin_url,
          build_xml_assignedRoles(request.params['memberID'], authentication_token),
          { "Content-Type" => "application/soap+xml; charset=utf-8" }
        )

        if @roles_response.code == 200
          @roles_response.body
        else
          raise "Bad get assigned roles response from server TCN"
        end
      end

      def get_user_info
        @user_response ||= RestClient.post( soap_poin_url,
          build_xml_getUserbyUserID(request.params['memberID'], authentication_token),
          { "Content-Type" => "application/soap+xml; charset=utf-8" }
        )

        if @user_response.code == 200
          @user_response.body
        else
          raise "Bad get user by user id response from server TCN"
        end
      end

      private

      def build_xml_assignedRoles user_id, key
        xml_builder = ::Builder::XmlMarkup.new
        xml_builder.instruct! :xml, :version=>"1.0", :encoding=>"utf-8"
        xml_builder.soap12 :Envelope, "xmlns:xsi"=>"http://www.w3.org/2001/XMLSchema-instance", "xmlns:xsd"=>"http://www.w3.org/2001/XMLSchema", "xmlns:soap12"=>"http://www.w3.org/2003/05/soap-envelope" do
          xml_builder.soap12 :Header do
            xml_builder.UserKey  xmlns: "http://NACBAweb_service.org/" do
              xml_builder.Key key
            end
          end
          xml_builder.soap12 :Body do
            xml_builder.assignedRoles xmlns: "http://NACBAweb_service.org/" do
              xml_builder.imisid user_id
            end
          end
        end
        xml_builder.target!
      end

      def build_xml_getUserbyUserID user_id, key
        xml_builder = ::Builder::XmlMarkup.new
        xml_builder.instruct! :xml, :version=>"1.0", :encoding=>"utf-8"
        xml_builder.soap12 :Envelope, "xmlns:xsi"=>"http://www.w3.org/2001/XMLSchema-instance", "xmlns:xsd"=>"http://www.w3.org/2001/XMLSchema", "xmlns:soap12"=>"http://www.w3.org/2003/05/soap-envelope" do
          xml_builder.soap12 :Header do
            xml_builder.UserKey  xmlns: "http://NACBAweb_service.org/" do
              xml_builder.Key key
            end
          end
          xml_builder.soap12 :Body do
            xml_builder.getUserbyUserID xmlns: "http://NACBAweb_service.org/" do
              xml_builder.iMISID user_id
            end
          end
        end
        xml_builder.target!
      end

      def authorize_url
        options.client_options.authorize_url
      end

      def authentication_token
        options.client_options.authentication_token
      end

      def soap_poin_url
        "#{options.client_options.site}#{options.client_options.soap_poin}"
      end
    end
  end
end
